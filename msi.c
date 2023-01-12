/*
 * MSI file support library
 *
 * Copyright (C) 2021 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * Reference specifications:
 * http://en.wikipedia.org/wiki/Compound_File_Binary_Format
 * https://msdn.microsoft.com/en-us/library/dd942138.aspx
 * https://github.com/microsoft/compoundfilereader
 */

#include <string.h>       /* memcmp */
#include "msi.h"

#define MIN(a,b) ((a) < (b) ? a : b)

static int recurse_entry(MSI_FILE *msi, uint32_t entryID, MSI_DIRENT *parent);

/* Get absolute address from sector and offset */
static const u_char *sector_offset_to_address(MSI_FILE *msi, uint32_t sector, uint32_t offset)
{
	if (sector >= MAXREGSECT || offset >= msi->m_sectorSize
			|| (msi->m_bufferLen - offset) / msi->m_sectorSize <= sector) {
		printf("Corrupted file\n");
		return NULL; /* FAILED */
	}
	return msi->m_buffer + (sector + 1) * msi->m_sectorSize + offset;
}

static uint32_t get_fat_sector_location(MSI_FILE *msi, uint32_t fatSectorNumber)
{
	uint32_t entriesPerSector, difatSectorLocation;
	const u_char *address;

	if (fatSectorNumber < DIFAT_IN_HEADER) {
		return LE_UINT32(msi->m_hdr->headerDIFAT[fatSectorNumber]);
	} else {
		fatSectorNumber -= DIFAT_IN_HEADER;
		entriesPerSector = msi->m_sectorSize / 4 - 1;
		difatSectorLocation = msi->m_hdr->firstDIFATSectorLocation;
		while (fatSectorNumber >= entriesPerSector) {
			fatSectorNumber -= entriesPerSector;
			address = sector_offset_to_address(msi, difatSectorLocation, msi->m_sectorSize - 4);
			if (!address) {
				printf("Failed to get a next sector address\n");
				return NOSTREAM; /* FAILED */
			}
			difatSectorLocation = GET_UINT32_LE(address);
		}
		address = sector_offset_to_address(msi, difatSectorLocation, fatSectorNumber * 4);
		if (!address) {
			printf("Failed to get a next sector address\n");
			return NOSTREAM; /* FAILED */
		}
		return GET_UINT32_LE(address);
	}
}

/* Lookup FAT */
static uint32_t get_next_sector(MSI_FILE *msi, uint32_t sector)
{
	const u_char *address;
	uint32_t entriesPerSector = msi->m_sectorSize / 4;
	uint32_t fatSectorNumber = sector / entriesPerSector;
	uint32_t fatSectorLocation = get_fat_sector_location(msi, fatSectorNumber);
	if (fatSectorLocation == NOSTREAM) {
		printf("Failed to get a fat sector location\n");
		return NOSTREAM; /* FAILED */
	}
	address = sector_offset_to_address(msi, fatSectorLocation, sector % entriesPerSector * 4);
	if (!address) {
		printf("Failed to get a next sector address\n");
		return NOSTREAM; /* FAILED */
	}
	return GET_UINT32_LE(address);
}

/* Locate the final sector/offset when original offset expands multiple sectors */
static int locate_final_sector(MSI_FILE *msi, uint32_t sector, uint32_t offset, uint32_t *finalSector, uint32_t *finalOffset)
{
	while (offset >= msi->m_sectorSize) {
		offset -= msi->m_sectorSize;
		sector = get_next_sector(msi, sector);
		if (sector == NOSTREAM) {
			printf("Failed to get a next sector\n");
			return 0; /* FAILED */
		}
	}
	*finalSector = sector;
	*finalOffset = offset;
	return 1; /* OK */
}

/* Get absolute address from mini sector and offset */
static const u_char *mini_sector_offset_to_address(MSI_FILE *msi, uint32_t sector, uint32_t offset)
{
	if (sector >= MAXREGSECT || offset >= msi->m_minisectorSize ||
			(msi->m_bufferLen - offset) / msi->m_minisectorSize <= sector) {
		printf("Corrupted file\n");
		return NULL; /* FAILED */
	}
	if (!locate_final_sector(msi, msi->m_miniStreamStartSector, sector * msi->m_minisectorSize + offset, &sector, &offset)) {
		printf("Failed to locate a final sector\n");
		return NULL; /* FAILED */
	}
	return sector_offset_to_address(msi, sector, offset);
}

/*
 * Copy as many as possible in each step
 * copylen typically iterate as: msi->m_sectorSize - offset --> msi->m_sectorSize --> msi->m_sectorSize --> ... --> remaining
 */
static int read_stream(MSI_FILE *msi, uint32_t sector, uint32_t offset, char *buffer, uint32_t len)
{
	if (!locate_final_sector(msi, sector, offset, &sector, &offset)) {
		printf("Failed to locate a final sector\n");
		return 0; /* FAILED */
	}
	while (len > 0) {
		const u_char *address;
		uint32_t copylen;
		address = sector_offset_to_address(msi, sector, offset);
		if (!address) {
			printf("Failed to get a next sector address\n");
			return 0; /* FAILED */
		}
		copylen = MIN(len, msi->m_sectorSize - offset);
		if (msi->m_buffer + msi->m_bufferLen < address + copylen) {
			printf("Corrupted file\n");
			return 0; /* FAILED */
		}
		memcpy(buffer, address, copylen);
		buffer += copylen;
		len -= copylen;
		sector = get_next_sector(msi, sector);
		if (sector == 0) {
			printf("Failed to get a next sector\n");
			return 0; /* FAILED */
		}
		offset = 0;
	}
	return 1; /* OK */
}

/* Lookup miniFAT */
static uint32_t get_next_mini_sector(MSI_FILE *msi, uint32_t miniSector)
{
	uint32_t sector, offset;
	const u_char *address;

	if (!locate_final_sector(msi, msi->m_hdr->firstMiniFATSectorLocation, miniSector * 4, &sector, &offset)) {
		printf("Failed to locate a final sector\n");
		return NOSTREAM; /* FAILED */
	}
	address = sector_offset_to_address(msi, sector, offset);
	if (!address) {
		printf("Failed to get a next mini sector address\n");
		return NOSTREAM; /* FAILED */
	}
	return GET_UINT32_LE(address);
}

static int locate_final_mini_sector(MSI_FILE *msi, uint32_t sector, uint32_t offset, uint32_t *finalSector, uint32_t *finalOffset)
{
	while (offset >= msi->m_minisectorSize) {
		offset -= msi->m_minisectorSize;
		sector = get_next_mini_sector(msi, sector);
		if (sector == NOSTREAM) {
			printf("Failed to get a next mini sector\n");
			return 0; /* FAILED */
		}
	}
	*finalSector = sector;
	*finalOffset = offset;
	return 1; /* OK */
}

/* Same logic as "read_stream" except that use mini stream functions instead */
static int read_mini_stream(MSI_FILE *msi, uint32_t sector, uint32_t offset, char *buffer, uint32_t len)
{
	if (!locate_final_mini_sector(msi, sector, offset, &sector, &offset)) {
		printf("Failed to locate a final mini sector\n");
		return 0; /* FAILED */
	}
	while (len > 0) {
		const u_char *address;
		uint32_t copylen;
		address = mini_sector_offset_to_address(msi, sector, offset);
		if (!address) {
			printf("Failed to get a next mini sector address\n");
			return 0; /* FAILED */
		}
		copylen = MIN(len, msi->m_minisectorSize - offset);
		if (msi->m_buffer + msi->m_bufferLen < address + copylen) {
			printf("Corrupted file\n");
			return 0; /* FAILED */
		}
		memcpy(buffer, address, copylen);
		buffer += copylen;
		len -= copylen;
		sector = get_next_mini_sector(msi, sector);
		if (sector == NOSTREAM) {
			printf("Failed to get a next mini sector\n");
			return 0; /* FAILED */
		}
		offset = 0;
	}
	return 1; /* OK */
}

 /*
  * Get file (stream) data start with "offset".
  * The buffer must have enough space to store "len" bytes. Typically "len" is derived by the steam length.
  */
int msi_file_read(MSI_FILE *msi, MSI_ENTRY *entry, uint32_t offset, char *buffer, uint32_t len)
{
	if (len < msi->m_hdr->miniStreamCutoffSize) {
		if (!read_mini_stream(msi, entry->startSectorLocation, offset, buffer, len))
			return 0; /* FAILED */
	} else {
		if (!read_stream(msi, entry->startSectorLocation, offset, buffer, len))
			return 0; /* FAILED */
	}
	return 1; /* OK */
}

/* Parse MSI_FILE_HDR struct */
static MSI_FILE_HDR *parse_header(char *data)
{
	MSI_FILE_HDR *header = (MSI_FILE_HDR *)OPENSSL_malloc(HEADER_SIZE);

	/* initialise 512 bytes */
	memset(header, 0, sizeof(MSI_FILE_HDR));
	memcpy(header->signature, data + HEADER_SIGNATURE, sizeof header->signature);
	/* Minor Version field SHOULD be set to 0x003E. */
	header->minorVersion = GET_UINT16_LE(data + HEADER_MINOR_VER);
	if (header->minorVersion !=0x003E ) {
		printf("Warning: Minor Version field SHOULD be 0x003E, but is: 0x%04X\n", header->minorVersion);
	}
	/* Major Version field MUST be set to either 0x0003 (version 3) or 0x0004 (version 4). */
	header->majorVersion = GET_UINT16_LE(data + HEADER_MAJOR_VER);
	if (header->majorVersion != 0x0003 && header->majorVersion != 0x0004) {
		printf("Unknown Major Version: 0x%04X\n", header->majorVersion);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	/* Byte Order field MUST be set to 0xFFFE, specifies little-endian byte order. */
	header->byteOrder = GET_UINT16_LE(data + HEADER_BYTE_ORDER);
	if (header->byteOrder != 0xFFFE) {
		printf("Unknown Byte Order: 0x%04X\n", header->byteOrder);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	/* Sector Shift field MUST be set to 0x0009, or 0x000c, depending on the Major Version field.
	 * This field specifies the sector size of the compound file as a power of 2. */
	header->sectorShift = GET_UINT16_LE(data + HEADER_SECTOR_SHIFT);
	if ((header->majorVersion == 0x0003 && header->sectorShift != 0x0009) ||
			(header->majorVersion == 0x0004 && header->sectorShift != 0x000C)) {
		printf("Unknown Sector Shift: 0x%04X\n", header->sectorShift);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	/* Mini Sector Shift field MUST be set to 0x0006.
	 * This field specifies the sector size of the Mini Stream as a power of 2.
	 * The sector size of the Mini Stream MUST be 64 bytes. */
	header->miniSectorShift = GET_UINT16_LE(data + HEADER_MINI_SECTOR_SHIFT);
	if (header->miniSectorShift != 0x0006) {
		printf("Unknown Mini Sector Shift: 0x%04X\n", header->miniSectorShift);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	/* Number of Directory Sectors field contains the count of the number
	 * of directory sectors in the compound file.
	 * If Major Version is 3, the Number of Directory Sectors MUST be zero. */
	header->numDirectorySector = GET_UINT32_LE(data + HEADER_DIR_SECTORS_NUM);
	if (header->majorVersion == 0x0003 && header->numDirectorySector != 0x00000000) {
		printf("Unsupported Number of Directory Sectors: 0x%08X\n", header->numDirectorySector);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	header->numFATSector = GET_UINT32_LE(data + HEADER_FAT_SECTORS_NUM);
	header->firstDirectorySectorLocation = GET_UINT32_LE(data + HEADER_DIR_SECTOR_LOC);
	header->transactionSignatureNumber = GET_UINT32_LE(data + HEADER_TRANSACTION);
	/* Mini Stream Cutoff Size field MUST be set to 0x00001000.
	 * This field specifies the maximum size of a user-defined data stream that is allocated
	 * from the mini FAT and mini stream, and that cutoff is 4,096 bytes.
	 * Any user-defined data stream that is greater than or equal to this cutoff size
	 * must be allocated as normal sectors from the FAT. */
	header->miniStreamCutoffSize = GET_UINT32_LE(data + HEADER_MINI_STREAM_CUTOFF);
	if (header->miniStreamCutoffSize != 0x00001000) {
		printf("Unsupported Mini Stream Cutoff Size: 0x%08X\n", header->miniStreamCutoffSize);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	header->firstMiniFATSectorLocation = GET_UINT32_LE(data + HEADER_MINI_FAT_SECTOR_LOC);
	header->numMiniFATSector = GET_UINT32_LE(data + HEADER_MINI_FAT_SECTORS_NUM);
	header->firstDIFATSectorLocation = GET_UINT32_LE(data + HEADER_DIFAT_SECTOR_LOC);
	header->numDIFATSector = GET_UINT32_LE(data + HEADER_DIFAT_SECTORS_NUM);
	memcpy(header->headerDIFAT, data + HEADER_DIFAT, sizeof header->headerDIFAT);
	return header;
}

/* Parse MSI_ENTRY struct */
static MSI_ENTRY *parse_entry(MSI_FILE *msi, const u_char *data, int is_root)
{
	uint32_t inlen;
	MSI_ENTRY *entry = (MSI_ENTRY *)OPENSSL_malloc(sizeof(MSI_ENTRY));

	/* initialise 128 bytes */
	memset(entry, 0, sizeof(MSI_ENTRY));
	entry->nameLen = GET_UINT16_LE(data + DIRENT_NAME_LEN);
	/* This length MUST NOT exceed 64, the maximum size of the Directory Entry Name field */
	if (entry->nameLen == 0 || entry->nameLen > 64) {
		printf("Corrupted Directory Entry Name Length\n");
		OPENSSL_free(entry);
		return NULL; /* FAILED */
	}
	memcpy(entry->name, data + DIRENT_NAME, entry->nameLen);
	/* The root directory entry's Name field MUST contain the null-terminated
	 * string "Root Entry" in Unicode UTF-16. */
	if (is_root && memcmp(entry->name, msi_root_entry, entry->nameLen)) {
		printf("Corrupted Root Directory Entry's Name\n");
		OPENSSL_free(entry);
		return NULL; /* FAILED */
	}
	entry->type = GET_UINT8_LE(data + DIRENT_TYPE);
	entry->colorFlag = GET_UINT8_LE(data + DIRENT_COLOUR);
	entry->leftSiblingID = GET_UINT32_LE(data + DIRENT_LEFT_SIBLING_ID);
	entry->rightSiblingID = GET_UINT32_LE(data + DIRENT_RIGHT_SIBLING_ID);
	entry->childID = GET_UINT32_LE(data + DIRENT_CHILD_ID);
	memcpy(entry->clsid, data + DIRENT_CLSID, 16);
	memcpy(entry->stateBits, data + DIRENT_STATE_BITS, 4);
	memcpy(entry->creationTime, data + DIRENT_CREATE_TIME, 8);
	/* The Creation Time field in the root storage directory entry MUST be all zeroes
	   but the Modified Time field in the root storage directory entry MAY be all zeroes */
	if (is_root && memcmp(entry->creationTime, msi_zeroes, 8)) {
		printf("Corrupted Root Directory Entry's Creation Time\n");
		OPENSSL_free(entry);
		return NULL; /* FAILED */
	}
	memcpy(entry->modifiedTime, data + DIRENT_MODIFY_TIME, 8);
	entry->startSectorLocation = GET_UINT32_LE(data + DIRENT_START_SECTOR_LOC);
	memcpy(entry->size, data + DIRENT_FILE_SIZE, 8);
	/* For a version 3 compound file 512-byte sector size, the value of this field
	   MUST be less than or equal to 0x80000000 */
	inlen = GET_UINT32_LE(entry->size);
	if ((msi->m_sectorSize == 0x0200 && inlen > 0x80000000)
			|| (msi->m_bufferLen <= inlen)) {
		printf("Corrupted Stream Size 0x%08X\n", inlen);
		OPENSSL_free(entry);
		return NULL; /* FAILED */
	}
	return entry;
}

/*
 * Get entry (directory or file) by its ID.
 * Pass "0" to get the root directory entry. -- This is the start point to navigate the compound file.
 * Use the returned object to access child entries.
 */
static MSI_ENTRY *get_entry(MSI_FILE *msi, uint32_t entryID, int is_root)
{
	uint32_t sector = 0;
	uint32_t offset = 0;
	const u_char *address;

	/* Corrupted file */
	if (!is_root && entryID == 0) {
		printf("Corrupted entryID\n");
		return NULL; /* FAILED */
	}
	if (msi->m_bufferLen / sizeof(MSI_ENTRY) <= entryID) {
		printf("Invalid argument entryID\n");
		return NULL; /* FAILED */
	}
	/* The first entry in the first sector of the directory chain is known as
	   the root directory entry so it can not contain the directory stream */
	if (msi->m_hdr->firstDirectorySectorLocation == 0 && entryID == 0) {
		printf("Corrupted First Directory Sector Location\n");
		return NULL; /* FAILED */
	}
	if (!locate_final_sector(msi, msi->m_hdr->firstDirectorySectorLocation,
			entryID * sizeof(MSI_ENTRY), &sector, &offset)) {
		printf("Failed to locate a final sector\n");
		return NULL; /* FAILED */
	}
	address = sector_offset_to_address(msi, sector, offset);
	if (!address) {
		printf("Failed to get a final address\n");
		return NULL; /* FAILED */
	}
	return parse_entry(msi, address, is_root);
}

MSI_ENTRY *msi_root_entry_get(MSI_FILE *msi)
{
	return get_entry(msi, 0, TRUE);
}

/* Parse MSI_FILE struct */
MSI_FILE *msi_file_new(char *buffer, uint32_t len)
{
	MSI_FILE *msi;
	MSI_ENTRY *root;
	MSI_FILE_HDR *header;

	if (buffer == NULL || len == 0) {
		printf("Invalid argument\n");
		return NULL; /* FAILED */
	}
	header = parse_header(buffer);
	if (!header) {
		printf("Failed to parse MSI_FILE_HDR struct\n");
		return NULL; /* FAILED */
	}
	msi = (MSI_FILE *)OPENSSL_malloc(sizeof(MSI_FILE));
	msi->m_buffer = (const u_char *)(buffer);
	msi->m_bufferLen = len;
	msi->m_hdr = header;
	msi->m_sectorSize = 1 << msi->m_hdr->sectorShift;
	msi->m_minisectorSize = 1 << msi->m_hdr->miniSectorShift;
	msi->m_miniStreamStartSector = 0;

	if (msi->m_bufferLen < sizeof *(msi->m_hdr) ||
			memcmp(msi->m_hdr->signature, msi_magic, sizeof msi_magic)) {
		printf("Wrong file format\n");
		msi_file_free(msi);
		return NULL; /* FAILED */
	}

	/* The file must contains at least 3 sectors */
	if (msi->m_bufferLen < msi->m_sectorSize * 3) {
		printf("The file must contains at least 3 sectors\n");
		msi_file_free(msi);
		return NULL; /* FAILED */
	}
	root = msi_root_entry_get(msi);
	if (!root) {
		printf("Failed to get msi root entry\n");
		msi_file_free(msi);
		return NULL; /* FAILED */
	}
	msi->m_miniStreamStartSector = root->startSectorLocation;
	OPENSSL_free(root);
	return msi;
}

/* Recursively create a tree of MSI_DIRENT structures */
int msi_dirent_new(MSI_FILE *msi, MSI_ENTRY *entry, MSI_DIRENT *parent, MSI_DIRENT **ret)
{
	MSI_DIRENT *dirent;
	static int cnt;
	static MSI_DIRENT *tortoise, *hare;

	if (!entry) {
		return 1; /* OK */
	}
	if (entry->nameLen == 0 || entry->nameLen > 64) {
		printf("Corrupted Directory Entry Name Length\n");
		return 0; /* FAILED */
	}
	/* detect cycles in previously visited entries (parents, siblings) */
	if (!ret) { /* initialized (non-root entry) */
		if ((entry->leftSiblingID != NOSTREAM && tortoise->entry->leftSiblingID == entry->leftSiblingID)
				|| (entry->rightSiblingID != NOSTREAM && tortoise->entry->rightSiblingID == entry->rightSiblingID)
				|| (entry->childID != NOSTREAM && tortoise->entry->childID == entry->childID)) {
			printf("MSI_ENTRY cycle detected at level %d\n", cnt);
			OPENSSL_free(entry);
			return 0; /* FAILED */
		}
	}

	dirent = (MSI_DIRENT *)OPENSSL_malloc(sizeof(MSI_DIRENT));
	memcpy(dirent->name, entry->name, entry->nameLen);
	dirent->nameLen = entry->nameLen;
	dirent->type = entry->type;
	dirent->entry = entry;
	dirent->children = sk_MSI_DIRENT_new_null();
	dirent->next = NULL; /* fail-safe */

	/* Floyd's cycle-finding algorithm */
	if (!ret) { /* initialized (non-root entry) */
		if (cnt++ & 1) /* move the tortoise every other invocation of msi_dirent_new() */
			tortoise = tortoise->next;
		hare->next = dirent; /* build a linked list of visited entries */
		hare = dirent; /* move the hare every time */
	} else { /* initialization needed (root entry) */
		cnt = 0;
		tortoise = dirent;
		hare = dirent;
	}

	if (parent && !sk_MSI_DIRENT_push(parent->children, dirent)) {
		printf("Failed to insert MSI_DIRENT\n");
		return 0; /* FAILED */
	}

	if (ret)
		*ret = dirent;

	if (!recurse_entry(msi, entry->leftSiblingID, parent)
			|| !recurse_entry(msi, entry->rightSiblingID, parent)
			|| !recurse_entry(msi, entry->childID, dirent)) {
		printf("Failed to add a sibling or a child to the tree\n");
		return 0; /* FAILED */
	}

	return 1; /* OK */
}

/* Add a sibling or a child to the tree */
/* NOTE: These links are a tree, not a linked list */
static int recurse_entry(MSI_FILE *msi, uint32_t entryID, MSI_DIRENT *parent)
{
	MSI_ENTRY *node;

	/* The special NOSTREAM (0xFFFFFFFF) value is used as a terminator */
	if (entryID == NOSTREAM) /* stop condition */
		return 1; /* OK */

	node = get_entry(msi, entryID, FALSE);
	if (!node) {
		printf("Corrupted ID: 0x%08X\n", entryID);
		return 0; /* FAILED */
	}

	if (!msi_dirent_new(msi, node, parent, NULL)) {
		return 0; /* FAILED */
	}

	return 1; /* OK */
}

/* Return DigitalSignature and MsiDigitalSignatureEx */
MSI_ENTRY *msi_signatures_get(MSI_DIRENT *dirent, MSI_ENTRY **dse)
{
	int i;
	MSI_ENTRY *ds = NULL;

	for (i = 0; i < sk_MSI_DIRENT_num(dirent->children); i++) {
		MSI_DIRENT *child = sk_MSI_DIRENT_value(dirent->children, i);
		if (!memcmp(child->name, digital_signature, MIN(child->nameLen, sizeof digital_signature))) {
			ds = child->entry;
		} else if (dse && !memcmp(child->name, digital_signature_ex, MIN(child->nameLen, sizeof digital_signature_ex))) {
			*dse = child->entry;
		} else {
			continue;
		}
	}
	return ds;
}

void msi_file_free(MSI_FILE *msi)
{
	if (!msi)
		return;
	OPENSSL_free(msi->m_hdr);
	OPENSSL_free(msi);
}

/* Recursively free MSI_DIRENT struct */
void msi_dirent_free(MSI_DIRENT *dirent)
{
	if (!dirent)
		return;
	sk_MSI_DIRENT_pop_free(dirent->children, msi_dirent_free);
	OPENSSL_free(dirent->entry);
	OPENSSL_free(dirent);
}

/* Sorted list of MSI streams in this order is needed for hashing */
static int dirent_cmp_hash(const MSI_DIRENT *const *a, const MSI_DIRENT *const *b)
{
	const MSI_DIRENT *dirent_a = *a;
	const MSI_DIRENT *dirent_b = *b;
	int diff = memcmp(dirent_a->name, dirent_b->name, MIN(dirent_a->nameLen, dirent_b->nameLen));
	/* apparently the longer wins */
	if (diff == 0) {
		return dirent_a->nameLen > dirent_b->nameLen ? -1 : 1;
	}
	return diff;
}

/* Sorting relationship for directory entries, the left sibling MUST always be less than the right sibling */
static int dirent_cmp_tree(const MSI_DIRENT *const *a, const MSI_DIRENT *const *b)
{
	const MSI_DIRENT *dirent_a = *a;
	const MSI_DIRENT *dirent_b = *b;
	uint16_t codepoint_a, codepoint_b;
	int i;

	if (dirent_a->nameLen != dirent_b->nameLen) {
		return dirent_a->nameLen < dirent_b->nameLen ? -1 : 1;
	}
	for (i=0; i<dirent_a->nameLen-2; i=i+2) {
		codepoint_a = GET_UINT16_LE(dirent_a->name + i);
		codepoint_b = GET_UINT16_LE(dirent_b->name + i);
		if (codepoint_a != codepoint_b) {
			return codepoint_a < codepoint_b ? -1 : 1;
		}
	}
	return 0;
}

/*
 * Calculate the pre-hash used for 'MsiDigitalSignatureEx'
 * signatures in MSI files.  The pre-hash hashes only metadata (file names,
 * file sizes, creation times and modification times), whereas the basic
 * 'DigitalSignature' MSI signature only hashes file content.
 *
 * The hash is written to the hash BIO.
 */

/* Hash a MSI stream's extended metadata */
static void prehash_metadata(MSI_ENTRY *entry, BIO *hash)
{
	if (entry->type != DIR_ROOT) {
		BIO_write(hash, entry->name, entry->nameLen - 2);
	}
	if (entry->type != DIR_STREAM) {
		BIO_write(hash, entry->clsid, sizeof entry->clsid);
	} else {
		BIO_write(hash, entry->size, (sizeof entry->size)/2);
	}
	BIO_write(hash, entry->stateBits, sizeof entry->stateBits);

	if (entry->type != DIR_ROOT) {
		BIO_write(hash, entry->creationTime, sizeof entry->creationTime);
		BIO_write(hash, entry->modifiedTime, sizeof entry->modifiedTime);
	}
}

/* Recursively hash a MSI directory's extended metadata */
int msi_prehash_dir(MSI_DIRENT *dirent, BIO *hash, int is_root)
{
	int i, ret = 0;
	STACK_OF(MSI_DIRENT) *children;

	if (!dirent || !dirent->children) {
		return ret;
	}
	children = sk_MSI_DIRENT_dup(dirent->children);
	prehash_metadata(dirent->entry, hash);
	sk_MSI_DIRENT_set_cmp_func(children, &dirent_cmp_hash);
	sk_MSI_DIRENT_sort(children);
	for (i = 0; i < sk_MSI_DIRENT_num(children); i++) {
		MSI_DIRENT *child = sk_MSI_DIRENT_value(children, i);
		if (is_root && (!memcmp(child->name, digital_signature, MIN(child->nameLen, sizeof digital_signature))
				|| !memcmp(child->name, digital_signature_ex, MIN(child->nameLen, sizeof digital_signature_ex)))) {
			continue;
		}
		if (child->type == DIR_STREAM) {
			prehash_metadata(child->entry, hash);
		}
		if (child->type == DIR_STORAGE) {
			if (!msi_prehash_dir(child, hash, 0)) {
				goto out;
			}
		}
	}
	ret = 1; /* OK */
out:
	sk_MSI_DIRENT_free(children);
	return ret;
}

/* Recursively hash a MSI directory (storage) */
int msi_hash_dir(MSI_FILE *msi, MSI_DIRENT *dirent, BIO *hash, int is_root)
 {
	int i, ret = 0;
	STACK_OF(MSI_DIRENT) *children;

	if (!dirent || !dirent->children) {
		return ret;
	}
	children = sk_MSI_DIRENT_dup(dirent->children);
	sk_MSI_DIRENT_set_cmp_func(children, &dirent_cmp_hash);
	sk_MSI_DIRENT_sort(children);

	for (i = 0; i < sk_MSI_DIRENT_num(children); i++) {
		MSI_DIRENT *child = sk_MSI_DIRENT_value(children, i);
		if (is_root && (!memcmp(child->name, digital_signature, MIN(child->nameLen, sizeof digital_signature))
				|| !memcmp(child->name, digital_signature_ex, MIN(child->nameLen, sizeof digital_signature_ex)))) {
			continue;
		}
		if (child->type == DIR_STREAM) {
			char *indata;
			uint32_t inlen = GET_UINT32_LE(child->entry->size);
			if (inlen == 0) {
				continue;
			}
			indata = (char *)OPENSSL_malloc(inlen);
			if (!msi_file_read(msi, child->entry, 0, indata, inlen)) {
				printf("Failed to read stream data\n");
				OPENSSL_free(indata);
				goto out;
			}
			BIO_write(hash, indata, (int)inlen);
			OPENSSL_free(indata);
		}
		if (child->type == DIR_STORAGE) {
			if (!msi_hash_dir(msi, child, hash, 0)) {
				printf("Failed to hash a MSI storage\n");
				goto out;
			}
		}
	}
	BIO_write(hash, dirent->entry->clsid, sizeof dirent->entry->clsid);
	ret = 1; /* OK */
out:
	sk_MSI_DIRENT_free(children);
	return ret;
}

/* Compute a simple sha1/sha256 message digest of the MSI file */
int msi_calc_digest(char *indata, int mdtype, u_char *mdbuf, uint32_t fileend)
{
	uint32_t n;
	int ret = 0;
	const EVP_MD *md = EVP_get_digestbynid(mdtype);
	BIO *bio = BIO_new_mem_buf(indata, (int)fileend);
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

	if (!EVP_DigestInit(mdctx, md)) {
		printf("Unable to set up the digest context\n");
		goto out;
	}
	memset(mdbuf, 0, EVP_MAX_MD_SIZE);
	(void)BIO_seek(bio, 0);

	n = 0;
	while (n < fileend) {
		int l;
		static u_char bfb[16*1024*1024];
		uint32_t want = fileend - n;
		if (want > sizeof bfb)
			want = sizeof bfb;
		l = BIO_read(bio, bfb, (int)want);
		if (l <= 0)
			break;
		EVP_DigestUpdate(mdctx, bfb, (size_t)l);
		n += (uint32_t)l;
	}
	EVP_DigestFinal(mdctx, mdbuf, NULL);
	ret = 1; /* OK */
out:
	EVP_MD_CTX_free(mdctx);
	BIO_free(bio);
	return ret;
}

static void ministream_append(MSI_OUT *out, char *buf, uint32_t len)
{
	uint32_t needSectors = (len + out->sectorSize - 1) / out->sectorSize;
	if (out->miniStreamLen + len >= (uint64_t)out->ministreamsMemallocCount * out->sectorSize) {
		out->ministreamsMemallocCount += needSectors;
		out->ministream = OPENSSL_realloc(out->ministream, (size_t)(out->ministreamsMemallocCount * out->sectorSize));
	}
	memcpy(out->ministream + out->miniStreamLen, buf, (size_t)len);
	out->miniStreamLen += len;
}

static void minifat_append(MSI_OUT *out, char *buf, uint32_t len)
{
	if (out->minifatLen == (uint64_t)out->minifatMemallocCount * out->sectorSize) {
		out->minifatMemallocCount += 1;
		out->minifat = OPENSSL_realloc(out->minifat, (size_t)(out->minifatMemallocCount * out->sectorSize));
	}
	memcpy(out->minifat + out->minifatLen, buf, (size_t)len);
	out->minifatLen += len;
}

static void fat_append(MSI_OUT *out, char *buf, uint32_t len)
{
	if (out->fatLen == (uint64_t)out->fatMemallocCount * out->sectorSize) {
		out->fatMemallocCount += 1;
		out->fat = OPENSSL_realloc(out->fat, (size_t)(out->fatMemallocCount * out->sectorSize));
	}
	memcpy(out->fat + out->fatLen, buf, (size_t)len);
	out->fatLen += len;
}

int msi_dirent_delete(MSI_DIRENT *dirent, const u_char *name, uint16_t nameLen)
{
	int i;

	for (i = 0; i < sk_MSI_DIRENT_num(dirent->children); i++) {
		MSI_DIRENT *child = sk_MSI_DIRENT_value(dirent->children, i);
		if (memcmp(child->name, name, MIN(child->nameLen, nameLen))) {
			continue;
		}
		if (child->type != DIR_STREAM) {
			printf("Can't delete or replace storages\n");
			return 0; /* FAILED */
		}
		sk_MSI_DIRENT_delete(dirent->children, i);
		msi_dirent_free(child);
	}
	return 1; /* OK */
}

static MSI_DIRENT *dirent_add(const u_char *name, uint16_t nameLen)
{
	MSI_DIRENT *dirent = (MSI_DIRENT *)OPENSSL_malloc(sizeof(MSI_DIRENT));
	MSI_ENTRY *entry = (MSI_ENTRY *)OPENSSL_malloc(sizeof(MSI_ENTRY));

	memcpy(dirent->name, name, nameLen);
	dirent->nameLen = nameLen;
	dirent->type = DIR_STREAM;
	dirent->children = sk_MSI_DIRENT_new_null();

	memcpy(entry->name, name, nameLen);
	entry->nameLen = nameLen;
	entry->type = DIR_STREAM;
	entry->colorFlag = BLACK_COLOR; /* make everything black */
	entry->leftSiblingID = NOSTREAM;
	entry->rightSiblingID = NOSTREAM;
	entry->childID = NOSTREAM;
	memset(entry->clsid, 0, 16);
	memset(entry->stateBits, 0, 4);
	memset(entry->creationTime, 0, 8);
	memset(entry->modifiedTime, 0, 8);
	entry->startSectorLocation = NOSTREAM;
	memset(entry->size, 0, 8);
	dirent->entry = entry;

	return dirent;
}

static int dirent_insert(MSI_DIRENT *dirent, const u_char *name, uint16_t nameLen)
{
	MSI_DIRENT *new_dirent;

	if (!msi_dirent_delete(dirent, name, nameLen)) {
		return 0; /* FAILED */
	}
	/* create new dirent */
	new_dirent = dirent_add(name, nameLen);
	sk_MSI_DIRENT_push(dirent->children, new_dirent);

	return 1; /* OK */
}

static int signature_insert(MSI_DIRENT *dirent, uint32_t len_msiex)
{
	if (len_msiex > 0) {
		if (!dirent_insert(dirent, digital_signature_ex, sizeof digital_signature_ex)) {
			return 0; /* FAILED */
		}
	} else {
		if (!msi_dirent_delete(dirent, digital_signature_ex, sizeof digital_signature_ex)) {
			return 0; /* FAILED */
		}
	}
	if (!dirent_insert(dirent, digital_signature, sizeof digital_signature)) {
			return 0; /* FAILED */
	}
	return 1; /* OK */
}

static uint32_t stream_read(MSI_FILE *msi, MSI_ENTRY *entry, u_char *p_msi, uint32_t len_msi,
		u_char *p_msiex, uint32_t len_msiex, char **indata, uint32_t inlen, int is_root)
{
	if (is_root && !memcmp(entry->name, digital_signature, sizeof digital_signature)) {
		*indata = (char *)p_msi;
		inlen = len_msi;
	} else if (is_root && !memcmp(entry->name, digital_signature_ex, sizeof digital_signature_ex)) {
		*indata = (char *)p_msiex;
		inlen = len_msiex;
	} else {
		if (!msi_file_read(msi, entry, 0, *indata, inlen)) {
			printf("Failed to read stream data\n");
			return 0; /* FAILED */
		}
	}
	return inlen;
}

/* Recursively handle data from MSI_DIRENT struct */
static int stream_handle(MSI_FILE *msi, MSI_DIRENT *dirent, u_char *p_msi, uint32_t len_msi,
		u_char *p_msiex, uint32_t len_msiex, BIO *outdata, MSI_OUT *out, int is_root)
{
	int i;

	if (dirent->type == DIR_ROOT) {
		if (len_msi > 0 && !signature_insert(dirent, len_msiex)) {
			printf("Insert new signature failed\n");
			return 0; /* FAILED */
		}
		out->ministreamsMemallocCount = (GET_UINT32_LE(dirent->entry->size) + out->sectorSize - 1)/out->sectorSize;
		out->ministream = OPENSSL_malloc((uint64_t)out->ministreamsMemallocCount * out->sectorSize);
	}
	for (i = 0; i < sk_MSI_DIRENT_num(dirent->children); i++) {
		MSI_DIRENT *child = sk_MSI_DIRENT_value(dirent->children, i);
		if (child->type == DIR_STORAGE) {
			if (!stream_handle(msi, child, NULL, 0, NULL, 0, outdata, out, 0)) {
				return 0; /* FAILED */
			}
		} else { /* DIR_STREAM */
			uint32_t inlen = GET_UINT32_LE(child->entry->size);
			char *indata = (char *)OPENSSL_malloc(inlen);
			char buf[MAX_SECTOR_SIZE];

			inlen = stream_read(msi, child->entry, p_msi, len_msi, p_msiex, len_msiex, &indata, inlen, is_root);
			if (inlen == 0) {
				continue;
			}
			/* set the size of the user-defined data if this is a stream object */
			PUT_UINT32_LE(inlen, buf);
			memcpy(child->entry->size, buf, sizeof child->entry->size);

			if (inlen < MINI_STREAM_CUTOFF_SIZE) {
				/* set the index into the mini FAT to track the chain of sectors through the mini stream */
				child->entry->startSectorLocation = out->miniSectorNum;
				ministream_append(out, indata, inlen);
				/* fill to the end with known data, such as all zeroes */
				if (inlen % msi->m_minisectorSize > 0) {
					uint32_t remain = msi->m_minisectorSize - inlen % msi->m_minisectorSize;
					memset(buf, 0, (size_t)remain);
					ministream_append(out, buf, remain);
				}
				while (inlen > msi->m_minisectorSize) {
					out->miniSectorNum += 1;
					PUT_UINT32_LE(out->miniSectorNum, buf);
					minifat_append(out, buf, 4);
					inlen -= msi->m_minisectorSize;
				}
				PUT_UINT32_LE(ENDOFCHAIN, buf);
				minifat_append(out, buf, 4);
				out->miniSectorNum += 1;
			} else {
				/* set the first sector location if this is a stream object */
				child->entry->startSectorLocation = out->sectorNum;
				/* stream save */
				BIO_write(outdata, indata, (int)inlen);
				/* fill to the end with known data, such as all zeroes */
				if (inlen % out->sectorSize > 0) {
					uint32_t remain = out->sectorSize - inlen % out->sectorSize;
					memset(buf, 0, (size_t)remain);
					BIO_write(outdata, buf, (int)remain);
				}
				/* set a sector chain in the FAT */
				while (inlen > out->sectorSize) {
					out->sectorNum += 1;
					PUT_UINT32_LE(out->sectorNum, buf);
					fat_append(out, buf, 4);
					inlen -= out->sectorSize;
				}
				PUT_UINT32_LE(ENDOFCHAIN, buf);
				fat_append(out, buf, 4);
				out->sectorNum += 1;
			}
			OPENSSL_free(indata);
		}
	}
	return 1; /* OK */
}

static void ministream_save(MSI_DIRENT *dirent, BIO *outdata, MSI_OUT *out)
{
	char buf[MAX_SECTOR_SIZE];
	uint32_t i, remain;
	uint32_t ministreamSectorsCount = (out->miniStreamLen + out->sectorSize - 1) / out->sectorSize;

	/* set the first sector of the mini stream in the entry root object */
	dirent->entry->startSectorLocation = out->sectorNum;
	/* ministream save */
	BIO_write(outdata, out->ministream, (int)out->miniStreamLen);
	OPENSSL_free(out->ministream);
	/* fill to the end with known data, such as all zeroes */
	if (out->miniStreamLen % out->sectorSize > 0) {
		remain = out->sectorSize - out->miniStreamLen % out->sectorSize;
		memset(buf, 0, (size_t)remain);
		BIO_write(outdata, buf, (int)remain);
	}
	/* set a sector chain in the FAT */
	for (i=1; i<ministreamSectorsCount; i++) {
		PUT_UINT32_LE(out->sectorNum + i, buf);
		fat_append(out, buf, 4);
	}
	/* mark the end of the mini stream data */
	PUT_UINT32_LE(ENDOFCHAIN, buf);
	fat_append(out, buf, 4);

	out->sectorNum += ministreamSectorsCount;
}

static void minifat_save(BIO *outdata, MSI_OUT *out)
{
	char buf[MAX_SECTOR_SIZE];
	uint32_t i, remain;

	/* set Mini FAT Starting Sector Location in the header */
	if (out->minifatLen == 0) {
		PUT_UINT32_LE(ENDOFCHAIN, buf);
		memcpy(out->header + HEADER_MINI_FAT_SECTOR_LOC, buf, 4);
		return;
	}
	PUT_UINT32_LE(out->sectorNum, buf);
	memcpy(out->header + HEADER_MINI_FAT_SECTOR_LOC, buf, 4);
	/* minifat save */
	BIO_write(outdata, out->minifat, (int)out->minifatLen);
	/* marks the end of the stream */
	PUT_UINT32_LE(ENDOFCHAIN, buf);
	BIO_write(outdata, buf, 4);
	out->minifatLen += 4;
	/* empty unallocated free sectors in the last Mini FAT sector */
	if (out->minifatLen % out->sectorSize > 0) {
		remain = out->sectorSize - out->minifatLen % out->sectorSize;
		memset(buf, (int)FREESECT, (size_t)remain);
		BIO_write(outdata, buf, (int)remain);
	}
	/* set a sector chain in the FAT */
	out->minifatSectorsCount = (out->minifatLen + out->sectorSize - 1) / out->sectorSize;
	for (i=1; i<out->minifatSectorsCount; i++) {
		PUT_UINT32_LE(out->sectorNum + i, buf);
		fat_append(out, buf, 4);
	}
	/* mark the end of the mini FAT chain */
	PUT_UINT32_LE(ENDOFCHAIN, buf);
	fat_append(out, buf, 4);

	out->sectorNum += out->minifatSectorsCount;
}

static char *msi_dirent_get(MSI_ENTRY *entry)
{
	char buf[8];
	char *data = OPENSSL_malloc(DIRENT_SIZE);

	/* initialise 128 bytes */
	memset(data, 0, DIRENT_SIZE);

	memcpy(data + DIRENT_NAME, entry->name, entry->nameLen);
	memset(data + DIRENT_NAME + entry->nameLen, 0, DIRENT_MAX_NAME_SIZE - entry->nameLen);
	PUT_UINT16_LE(entry->nameLen, buf);
	memcpy(data + DIRENT_NAME_LEN, buf, 2);
	PUT_UINT8_LE(entry->type, buf);
	memcpy(data + DIRENT_TYPE, buf, 1);
	PUT_UINT8_LE(entry->colorFlag, buf);
	memcpy(data + DIRENT_COLOUR, buf, 1);
	PUT_UINT32_LE(entry->leftSiblingID, buf);
	memcpy(data + DIRENT_LEFT_SIBLING_ID, buf, 4);
	PUT_UINT32_LE(entry->rightSiblingID, buf);
	memcpy(data + DIRENT_RIGHT_SIBLING_ID, buf, 4);
	PUT_UINT32_LE(entry->childID, buf);
	memcpy(data + DIRENT_CHILD_ID, buf, 4);
	memcpy(data + DIRENT_CLSID, entry->clsid, 16);
	memcpy(data + DIRENT_STATE_BITS, entry->stateBits, 4);
	memcpy(data + DIRENT_CREATE_TIME, entry->creationTime, 8);
	memcpy(data + DIRENT_MODIFY_TIME, entry->modifiedTime, 8);
	PUT_UINT32_LE(entry->startSectorLocation, buf);
	memcpy(data + DIRENT_START_SECTOR_LOC, buf, 4);
	memcpy(data + DIRENT_FILE_SIZE, entry->size, 4);
	memset(data + DIRENT_FILE_SIZE + 4, 0, 4);
	return data;
}

static char *msi_unused_dirent_get()
{
	char *data = OPENSSL_malloc(DIRENT_SIZE);

	/* initialise 127 bytes */
	memset(data, 0, DIRENT_SIZE);

	memset(data + DIRENT_LEFT_SIBLING_ID, (int)NOSTREAM, 4);
	memset(data + DIRENT_RIGHT_SIBLING_ID, (int)NOSTREAM, 4);
	memset(data + DIRENT_CHILD_ID, (int)NOSTREAM, 4);
	return data;
}

static int dirents_save(MSI_DIRENT *dirent, BIO *outdata, MSI_OUT *out, uint32_t *streamId, int count, int last)
{
	int i, childenNum;
	char *entry;
	STACK_OF(MSI_DIRENT) *children;
	
	if (!dirent || !dirent->children) {
		return count;
	}
	children = sk_MSI_DIRENT_dup(dirent->children);
	sk_MSI_DIRENT_set_cmp_func(children, &dirent_cmp_tree);
	sk_MSI_DIRENT_sort(children);
	childenNum = sk_MSI_DIRENT_num(children);
	/* make everything black */
	dirent->entry->colorFlag = BLACK_COLOR;
	dirent->entry->leftSiblingID = NOSTREAM;
	if (dirent->type == DIR_STORAGE) {
		if (last) {
			dirent->entry->rightSiblingID = NOSTREAM;
		} else {
			/* make linked list rather than tree, only use next - right sibling */
			count += childenNum;
			dirent->entry->rightSiblingID = *streamId + (uint32_t)count + 1;
		}
	} else { /* DIR_ROOT */
		dirent->entry->rightSiblingID = NOSTREAM;
	}
	dirent->entry->childID = *streamId + 1;
	entry = msi_dirent_get(dirent->entry);
	BIO_write(outdata, entry, DIRENT_SIZE);
	OPENSSL_free(entry);
	out->dirtreeLen += DIRENT_SIZE;
	for (i = 0; i < childenNum; i++) {
		MSI_DIRENT *child = sk_MSI_DIRENT_value(children, i);
		int last_dir = i == childenNum - 1 ? 1 : 0;
		*streamId += 1;
		if (child->type == DIR_STORAGE) {
			count += dirents_save(child, outdata, out, streamId, count, last_dir);
		} else { /* DIR_STREAM */
			count = 0;
			child->entry->colorFlag = BLACK_COLOR;
			child->entry->leftSiblingID = NOSTREAM;
			if (last_dir) {
				child->entry->rightSiblingID = NOSTREAM;
			} else {
				child->entry->rightSiblingID = *streamId + 1;
			}
			entry = msi_dirent_get(child->entry);
			BIO_write(outdata, entry, DIRENT_SIZE);
			OPENSSL_free(entry);
			out->dirtreeLen += DIRENT_SIZE;
		}
	}
	sk_MSI_DIRENT_free(children);
	return count;
}

static void dirtree_save(MSI_DIRENT *dirent, BIO *outdata, MSI_OUT *out)
{
	char buf[MAX_SECTOR_SIZE];
	char *unused_entry;
	uint32_t i, remain, streamId = 0;

	/* set Directory Starting Sector Location in the header */
	PUT_UINT32_LE(out->sectorNum, buf);
	memcpy(out->header + HEADER_DIR_SECTOR_LOC, buf, 4);

	/* set the size of the mini stream in the root object */
	if (dirent->type == DIR_ROOT) {
		PUT_UINT32_LE(out->miniStreamLen, buf);
		memcpy(dirent->entry->size, buf, sizeof dirent->entry->size);
	}
	/* sort and save all directory entries */
	dirents_save(dirent, outdata, out, &streamId, 0, 0);
	/* set free (unused) directory entries */
	unused_entry = msi_unused_dirent_get();
	if (out->dirtreeLen % out->sectorSize > 0) {
		remain = out->sectorSize - out->dirtreeLen % out->sectorSize;
		while (remain > 0) {
			BIO_write(outdata, unused_entry, DIRENT_SIZE);
			remain -= DIRENT_SIZE;
		}
	}
	OPENSSL_free(unused_entry);
	/* set a sector chain in the FAT */
	out->dirtreeSectorsCount = (out->dirtreeLen + out->sectorSize - 1) / out->sectorSize;
	for (i=1; i<out->dirtreeSectorsCount; i++) {
		PUT_UINT32_LE(out->sectorNum + i, buf);
		fat_append(out, buf, 4);
	}
	/* mark the end of the directory chain */
	PUT_UINT32_LE(ENDOFCHAIN, buf);
	fat_append(out, buf, 4);

	out->sectorNum += out->dirtreeSectorsCount;
}

static int fat_save(BIO *outdata, MSI_OUT *out)
{
	char buf[MAX_SECTOR_SIZE];
	uint32_t i, remain;

	remain = (out->fatLen + out->sectorSize - 1) / out->sectorSize;
	out->fatSectorsCount = (out->fatLen + remain * 4 + out->sectorSize - 1) / out->sectorSize;

	/* mark FAT sectors in the FAT chain */
	PUT_UINT32_LE(FATSECT, buf);
	for (i=0; i<out->fatSectorsCount; i++) {
		fat_append(out, buf, 4);
	}
	/* set 109 FAT sectors in HEADER_DIFAT table */
	for (i=0; i<MIN(out->fatSectorsCount, DIFAT_IN_HEADER); i++) {
		PUT_UINT32_LE(out->sectorNum + i, buf);
		memcpy(out->header + HEADER_DIFAT + i * 4, buf, 4);
	}
	out->sectorNum += out->fatSectorsCount;

	if (out->fatSectorsCount > DIFAT_IN_HEADER) {
		/* TODO set FAT sectors in DIFAT sector */
		printf("DIFAT sectors are not supported\n");
		return 0; /* FAILED */
	}
	/* empty unallocated free sectors in the last FAT sector */
	if (out->fatLen % out->sectorSize > 0) {
		remain = out->sectorSize - out->fatLen % out->sectorSize;
		memset(buf, (int)FREESECT, (size_t)remain);
		fat_append(out, buf, remain);
	}
	BIO_write(outdata, out->fat, (int)out->fatLen);
	return 1; /* OK */
}

static void header_save(BIO *outdata, MSI_OUT *out)
{
	char buf[MAX_SECTOR_SIZE];
	uint32_t remain;

	/* set Number of FAT sectors in the header */
	PUT_UINT32_LE(out->fatSectorsCount, buf);
	memcpy(out->header + HEADER_FAT_SECTORS_NUM, buf, 4);

	/* set Number of Mini FAT sectors in the header */
	PUT_UINT32_LE(out->minifatSectorsCount, buf);
	memcpy(out->header + HEADER_MINI_FAT_SECTORS_NUM, buf, 4);

	/* set Number of Directory Sectors in the header if Major Version is 4 */
	if (out->sectorSize == 4096) {
		PUT_UINT32_LE(out->dirtreeSectorsCount, buf);
		memcpy(out->header + HEADER_DIR_SECTORS_NUM, buf, 4);
	}
	(void)BIO_seek(outdata, 0);
	BIO_write(outdata, out->header, HEADER_SIZE);

	remain = out->sectorSize - HEADER_SIZE;
	memset(buf, 0, (size_t)remain);
	BIO_write(outdata, buf, (int)remain);
}

static char *header_new(MSI_FILE_HDR *hdr, MSI_OUT *out)
{
	int i;
	char buf[4];
	char *data = OPENSSL_malloc(HEADER_SIZE);
	static u_char dead_food[] = {
		0xde, 0xad, 0xf0, 0x0d
	};

	/* initialise 512 bytes */
	memset(data, 0, HEADER_SIZE);

	memcpy(data + HEADER_SIGNATURE, msi_magic, sizeof msi_magic);
	memset(data + HEADER_CLSID, 0, 16);
	PUT_UINT16_LE(hdr->minorVersion, buf);
	memcpy(data + HEADER_MINOR_VER, buf, 2);
	if (out->sectorSize == 4096) {
		PUT_UINT16_LE(0x0004, buf);
	} else {
		PUT_UINT16_LE(0x0003, buf);
	}
	memcpy(data + HEADER_MAJOR_VER, buf, 2);
	PUT_UINT16_LE(hdr->byteOrder, buf);
	memcpy(data + HEADER_BYTE_ORDER, buf, 2);
	PUT_UINT16_LE(hdr->sectorShift, buf);
	if (out->sectorSize == 4096) {
		PUT_UINT16_LE(0x000C, buf);
	} else {
		PUT_UINT16_LE(0x0009, buf);
	}
	memcpy(data + HEADER_SECTOR_SHIFT, buf, 2);
	PUT_UINT16_LE(hdr->miniSectorShift, buf);
	memcpy(data + HEADER_MINI_SECTOR_SHIFT, buf, 2);
	memset(data + RESERVED, 0, 6);
	memset(data + HEADER_DIR_SECTORS_NUM, 0, 4); /* not used for version 3 */
	memcpy(data + HEADER_FAT_SECTORS_NUM, dead_food, 4);
	memcpy(data + HEADER_DIR_SECTOR_LOC, dead_food, 4);
	memset(data + HEADER_TRANSACTION, 0, 4);     /* reserved */
	PUT_UINT32_LE(MINI_STREAM_CUTOFF_SIZE, buf);
	memcpy(data + HEADER_MINI_STREAM_CUTOFF, buf, 4);
	memcpy(data + HEADER_MINI_FAT_SECTOR_LOC, dead_food, 4);
	memcpy(data + HEADER_MINI_FAT_SECTORS_NUM, dead_food, 4);
	PUT_UINT32_LE(ENDOFCHAIN, buf);
	memcpy(data + HEADER_DIFAT_SECTOR_LOC, buf, 4);
	memset(data + HEADER_DIFAT_SECTORS_NUM, 0, 4); /* no DIFAT */
	memcpy(data + HEADER_DIFAT, dead_food, 4);     /* sector number for FAT */
	for (i = 1; i < DIFAT_IN_HEADER; i++) {
		memset(data + HEADER_DIFAT + 4*i, (int)FREESECT, 4); /* free FAT sectors */
	}
	return data;
}

static int msiout_set(MSI_FILE *msi, uint32_t len_msi, uint32_t len_msiex, MSI_OUT *out)
{
	uint32_t msi_size, msiex_size;

	out->sectorSize = msi->m_sectorSize;

	if (len_msi <= MINI_STREAM_CUTOFF_SIZE) {
		msi_size = ((len_msi + msi->m_minisectorSize - 1) / msi->m_minisectorSize) * msi->m_minisectorSize;
	} else {
		msi_size = ((len_msi + msi->m_sectorSize - 1) / msi->m_sectorSize) * msi->m_sectorSize;
	}
	msiex_size = ((len_msiex + msi->m_minisectorSize - 1) / msi->m_minisectorSize) * msi->m_minisectorSize;
	/*
	 * no DIFAT sectors will be needed in a file that is smaller than
	 *  6,813 MB (version 3 files), respectively 436,004 MB (version 4 files)
	 */
	if (msi->m_bufferLen + msi_size + msiex_size > 7143936) {
		out->sectorSize = 4096;
	}
	if (msi->m_bufferLen + msi_size + msiex_size > 457183232) {
		printf("DIFAT sectors are not supported\n");
		return 0;/* FAILED */
	}
	out->header = header_new(msi->m_hdr, out);
	out->minifatMemallocCount = msi->m_hdr->numMiniFATSector;
	out->fatMemallocCount = msi->m_hdr->numFATSector;
	out->ministream = NULL;
	out->minifat = OPENSSL_malloc((uint64_t)out->minifatMemallocCount * out->sectorSize);
	out->fat = OPENSSL_malloc((uint64_t)out->fatMemallocCount * out->sectorSize);
	out->miniSectorNum = 0;
	out->sectorNum = 0;
	return 1; /* OK */
}

int msi_file_write(MSI_FILE *msi, MSI_DIRENT *dirent, u_char *p_msi, uint32_t len_msi,
		u_char *p_msiex, uint32_t len_msiex, BIO *outdata)
{
	MSI_OUT out;
	int ret = 0;

	memset(&out, 0, sizeof(MSI_OUT));
	if (!msiout_set(msi, len_msi, len_msiex, &out)) {
		goto out; /* FAILED */
	}
	(void)BIO_seek(outdata, out.sectorSize);

	if (!stream_handle(msi, dirent, p_msi, len_msi, p_msiex, len_msiex, outdata, &out, 1)) {
		goto out; /* FAILED */
	}
	ministream_save(dirent, outdata, &out);
	minifat_save(outdata, &out);
	dirtree_save(dirent, outdata, &out);
	if (!fat_save(outdata, &out)) {
		goto out; /* FAILED */
	}
	header_save(outdata, &out);
	ret = 1; /* OK */
out:
	OPENSSL_free(out.header);
	OPENSSL_free(out.fat);
	OPENSSL_free(out.minifat);
	return ret;
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
