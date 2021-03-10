/*
 * Microsoft Compound File Reader
 * http://en.wikipedia.org/wiki/Compound_File_Binary_Format
 * https://msdn.microsoft.com/en-us/library/dd942138.aspx
 * https://github.com/microsoft/compoundfilereader
 */

#include <string.h>       /* memcmp */
#include "msi.h"

#define MIN(a,b) ((a) < (b) ? a : b)

/* Get absolute address from sector and offset */
static const unsigned char *sector_offset_to_address(MSI_FILE *msi, size_t sector, size_t offset)
{
	if (sector >= MAXREGSECT || offset >= msi->m_sectorSize ||
			msi->m_bufferLen <= msi->m_sectorSize * sector + msi->m_sectorSize + offset) {
		return NULL; /* FAILED */
	}
	return msi->m_buffer + msi->m_sectorSize + msi->m_sectorSize * sector + offset;
}

static size_t get_fat_sector_location(MSI_FILE *msi, size_t fatSectorNumber)
{
	if (fatSectorNumber < DIFAT_IN_HEADER) {
		return msi->m_hdr->headerDIFAT[fatSectorNumber];
	} else {
		fatSectorNumber -= DIFAT_IN_HEADER;
		size_t entriesPerSector = msi->m_sectorSize / 4 - 1;
		size_t difatSectorLocation = msi->m_hdr->firstDIFATSectorLocation;
		while (fatSectorNumber >= entriesPerSector) {
			fatSectorNumber -= entriesPerSector;
			const unsigned char *address = sector_offset_to_address(msi, difatSectorLocation, msi->m_sectorSize - 4);
			difatSectorLocation = GET_UINT32_LE(address);
		}
		return GET_UINT32_LE(sector_offset_to_address(msi, difatSectorLocation, fatSectorNumber * 4));
	}
}

/* Lookup FAT */
static size_t get_next_sector(MSI_FILE *msi, size_t sector)
{
	size_t entriesPerSector = msi->m_sectorSize / 4;
	size_t fatSectorNumber = sector / entriesPerSector;
	size_t fatSectorLocation = get_fat_sector_location(msi, fatSectorNumber);
	return GET_UINT32_LE(sector_offset_to_address(msi, fatSectorLocation, sector % entriesPerSector * 4));
}

/* Locate the final sector/offset when original offset expands multiple sectors */
static void locate_final_sector(MSI_FILE *msi, size_t sector, size_t offset, size_t *finalSector, size_t *finalOffset)
{
	while (offset >= msi->m_sectorSize) {
		offset -= msi->m_sectorSize;
		sector = get_next_sector(msi, sector);
	}
	*finalSector = sector;
	*finalOffset = offset;
}

/* Get absolute address from mini sector and offset */
static const unsigned char *mini_sector_offset_to_address(MSI_FILE *msi, size_t sector, size_t offset)
{
	if (sector >= MAXREGSECT || offset >= msi->m_minisectorSize ||
		msi->m_bufferLen <= msi->m_minisectorSize * sector + offset) {
		return NULL; /* FAILED */
	}
	locate_final_sector(msi, msi->m_miniStreamStartSector, sector *msi->m_minisectorSize + offset, &sector, &offset);
	return sector_offset_to_address(msi, sector, offset);
}

/*
 * Copy as many as possible in each step
 * copylen typically iterate as: msi->m_sectorSize - offset --> msi->m_sectorSize --> msi->m_sectorSize --> ... --> remaining
 */
static int read_stream(MSI_FILE *msi, size_t sector, size_t offset, char *buffer, size_t len)
{
	locate_final_sector(msi, sector, offset, &sector, &offset);
	while (len > 0) {
		const unsigned char *address = sector_offset_to_address(msi, sector, offset);
		size_t copylen = MIN(len, msi->m_sectorSize - offset);
		if (msi->m_buffer + msi->m_bufferLen < address + copylen) {
			return 0; /* FAILED */
		}
		memcpy(buffer, address, copylen);
		buffer += copylen;
		len -= copylen;
		sector = get_next_sector(msi, sector);
	offset = 0;
	}
	return 1;
}

/* Lookup miniFAT */
static size_t get_next_mini_sector(MSI_FILE *msi, size_t miniSector)
{
	size_t sector, offset;
	locate_final_sector(msi, msi->m_hdr->firstMiniFATSectorLocation, miniSector * 4, &sector, &offset);
	return GET_UINT32_LE(sector_offset_to_address(msi, sector, offset));
}

static void locate_final_mini_sector(MSI_FILE *msi, size_t sector, size_t offset, size_t *finalSector, size_t *finalOffset)
{
	while (offset >= msi->m_minisectorSize) {
		offset -= msi->m_minisectorSize;
		sector = get_next_mini_sector(msi, sector);
	}
	*finalSector = sector;
	*finalOffset = offset;
}

/* Same logic as "read_stream" except that use mini stream functions instead */
static int read_mini_stream(MSI_FILE *msi, size_t sector, size_t offset, char *buffer, size_t len)
{
	locate_final_mini_sector(msi, sector, offset, &sector, &offset);
	while (len > 0) {
		const unsigned char *address = mini_sector_offset_to_address(msi, sector, offset);
		size_t copylen = MIN(len, msi->m_minisectorSize - offset);
		if (!address || msi->m_buffer + msi->m_bufferLen < address + copylen) {
			return 0; /* FAILED */
		}
		memcpy(buffer, address, copylen);
		buffer += copylen;
		len -= copylen;
		sector = get_next_mini_sector(msi, sector);
		offset = 0;
	}
	return 1;
}

 /*
  * Get file (stream) data start with "offset".
  * The buffer must have enough space to store "len" bytes. Typically "len" is derived by the steam length.
  */
int msi_read_file(MSI_FILE *msi, MSI_FILE_ENTRY *entry, size_t offset, char *buffer, size_t len)
{
	if (len < msi->m_hdr->miniStreamCutoffSize) {
		if (!read_mini_stream(msi, entry->startSectorLocation, offset, buffer, len))
			return 0; /* FAILED */
	} else {
		if (!read_stream(msi, entry->startSectorLocation, offset, buffer, len))
			return 0; /* FAILED */
	}
	return 1;
}

/* Parse MSI_FILE_HDR struct */
static MSI_FILE_HDR *parse_header(char *data)
{
	MSI_FILE_HDR *header = (MSI_FILE_HDR *)OPENSSL_malloc(sizeof(MSI_FILE_HDR));
	if (!data) {
		memset(&header, 0, sizeof(MSI_FILE_HDR));
	} else {
		memcpy(header->signature, data + HEADER_SIGNATURE, sizeof(header->signature));
		header->minorVersion = GET_UINT16_LE(data + HEADER_MINOR_VER);
		header->majorVersion = GET_UINT16_LE(data + HEADER_MAJOR_VER);
		header->byteOrder = GET_UINT16_LE(data + HEADER_BYTE_ORDER);
		header->sectorShift = GET_UINT16_LE(data + HEADER_SECTOR_SHIFT);
		header->miniSectorShift = GET_UINT16_LE(data + HEADER_MINI_SECTOR_SHIFT);
		header->numDirectorySector = GET_UINT32_LE(data + HEADER_DIR_SECTOR);
		header->numFATSector = GET_UINT32_LE(data + HEADER_FAT_SECTOR);
		header->firstDirectorySectorLocation = GET_UINT32_LE(data + HEADER_DIR_SECTOR_LOC);
		header->transactionSignatureNumber = GET_UINT32_LE(data + HEADER_TRANSACTION);
		header->miniStreamCutoffSize = GET_UINT32_LE(data + HEADER_STREAM_CUTOFF_SIZE);
		header->firstMiniFATSectorLocation = GET_UINT32_LE(data + HEADER_MINI_FAT_SECTOR_LOC);
		header->numMiniFATSector = GET_UINT32_LE(data + HEADER_MINI_FAT_SECTOR);
		header->firstDIFATSectorLocation = GET_UINT32_LE(data + HEADER_DIFAT_FAT_SECTOR_LOC);
		header->numDIFATSector = GET_UINT32_LE(data + HEADER_DIFAT_FAT_SECTOR);
		memcpy(header->headerDIFAT, data + HEADER_DIFAT, sizeof(header->headerDIFAT));
	}
	return header;
}

/* Parse MSI_FILE_ENTRY struct */
static MSI_FILE_ENTRY *parse_entry(const unsigned char *data)
{
	MSI_FILE_ENTRY *entry = (MSI_FILE_ENTRY *)OPENSSL_malloc(sizeof(MSI_FILE_ENTRY));
	entry->nameLen = GET_UINT16_LE(data + DIRENT_NAME_LEN);
	memcpy(entry->name, data + DIRENT_NAME, entry->nameLen);
	entry->type = GET_UINT8_LE(data + DIRENT_TYPE);
	entry->colorFlag = GET_UINT8_LE(data + DIRENT_COLOUR);
	entry->leftSiblingID = GET_UINT32_LE(data + DIRENT_LEFT_SIBLING_ID);
	entry->rightSiblingID = GET_UINT32_LE(data + DIRENT_RIGHT_SIBLING_ID);
	entry->childID = GET_UINT32_LE(data + DIRENT_CHILD_ID);
	memcpy(entry->clsid, data + DIRENT_CLSID, sizeof(entry->clsid));
	memcpy(entry->stateBits, data + DIRENT_STATE_BITS, sizeof(entry->stateBits));
	memcpy(entry->creationTime, data + DIRENT_CREATE_TIME, sizeof(entry->creationTime));
	memcpy(entry->modifiedTime, data + DIRENT_MODIFY_TIME, sizeof(entry->modifiedTime));
	entry->startSectorLocation = GET_UINT32_LE(data + DIRENT_START_SECTOR_LOC);
	memcpy(entry->size, data + DIRENT_FILE_SIZE, sizeof(entry->size));
	return entry;
}

/*
 * Get entry (directory or file) by its ID.
 * Pass "0" to get the root directory entry. -- This is the start point to navigate the compound file.
 * Use the returned object to access child entries.
 */
static MSI_FILE_ENTRY *get_entry(MSI_FILE *msi, size_t entryID)
{
	/* The special value NOSTREAM (0xFFFFFFFF) is used as a terminator */
	if (entryID == NOSTREAM) {
		return NULL; /* FAILED */
	}
	if (msi->m_bufferLen / sizeof(MSI_FILE_ENTRY) <= entryID) {
		printf("Invalid argument entryID\n");
		return NULL; /* FAILED */
	}
	size_t sector = 0;
	size_t offset = 0;
	locate_final_sector(msi, msi->m_hdr->firstDirectorySectorLocation, entryID * sizeof(MSI_FILE_ENTRY), &sector, &offset);
	const unsigned char *address = sector_offset_to_address(msi, sector, offset);
	return parse_entry(address);
}

MSI_FILE_ENTRY *msi_get_root_entry(MSI_FILE *msi)
{
	return get_entry(msi, 0);
}

/* Parse MSI_FILE struct */
MSI_FILE *msi_msifile_new(char *buffer, size_t len)
{
	MSI_FILE *msi;
	MSI_FILE_ENTRY *root;

	if (buffer == NULL || len == 0) {
		printf("Invalid argument\n");
		return NULL; /* FAILED */
	}
	msi = (MSI_FILE *)OPENSSL_malloc(sizeof(MSI_FILE));
	msi->m_buffer = (const unsigned char *)(buffer);
	msi->m_bufferLen = len;
	msi->m_hdr = parse_header(buffer);
	msi->m_sectorSize = 512;
	msi->m_minisectorSize = 64;
	msi->m_miniStreamStartSector = 0;

	if (msi->m_bufferLen < sizeof(*(msi->m_hdr)) ||
			memcmp(msi->m_hdr->signature, msi_magic, sizeof(msi_magic))) {
		printf("Wrong file format\n");
		return NULL; /* FAILED */
	}
	msi->m_sectorSize = msi->m_hdr->majorVersion == 3 ? 512 : 4096;

	/* The file must contains at least 3 sectors */
	if (msi->m_bufferLen < msi->m_sectorSize * 3) {
		printf("The file must contains at least 3 sectors\n");
		return NULL; /* FAILED */
	}
	root = msi_get_root_entry(msi);
	if (root == NULL) {
		printf("File corrupted\n");
		return NULL; /* FAILED */
	}
	msi->m_miniStreamStartSector = root->startSectorLocation;
	OPENSSL_free(root);
	return msi;
}

void msi_msifile_free(MSI_FILE *msi)
{
	OPENSSL_free(msi->m_hdr);
	OPENSSL_free(msi);
}

MSI_FILE_HDR *msi_get_file_info(MSI_FILE *msi)
{
	return msi->m_hdr;
}

static int msi_dirent_cmp(const MSI_DIR_ENTRY *const *a, const MSI_DIR_ENTRY *const *b)
{
	const MSI_DIR_ENTRY *dirent_a = *a;
	const MSI_DIR_ENTRY *dirent_b = *b;
	int diff = memcmp(dirent_a->name, dirent_b->name, MIN(dirent_a->nameLen, dirent_b->nameLen));
	/* apparently the longer wins */
	if (diff == 0) {
		return dirent_a->nameLen > dirent_b->nameLen ? 1 : -1;
	}
	return diff;
}

/* Recursively parse MSI_DIR_ENTRY struct */
MSI_DIR_ENTRY *msi_dirent_new(MSI_FILE *msi, MSI_FILE_ENTRY *entry,
		MSI_DIR_ENTRY *parent, MSI_FILE_ENTRY **ds, MSI_FILE_ENTRY **dse)
{
	if (!entry) {
		return NULL;
	}
	if (!memcmp(entry->name, digital_signature, sizeof(digital_signature))) {
		*ds = entry;
	}
	if (!memcmp(entry->name, digital_signature_ex, sizeof(digital_signature_ex))) {
		*dse = entry;
	}
	MSI_DIR_ENTRY *dirent = (MSI_DIR_ENTRY *)OPENSSL_malloc(sizeof(MSI_DIR_ENTRY));
	memcpy(dirent->name, entry->name, entry->nameLen);
	dirent->nameLen = entry->nameLen;
	dirent->type = entry->type;
	dirent->entry = entry;
	/* sorted list of MSI streams in the order is needed for hashing */
	dirent->children = sk_MSI_DIR_ENTRY_new(&msi_dirent_cmp);

	if (parent != NULL) {
		sk_MSI_DIR_ENTRY_push(parent->children, dirent);
	}

	/* NOTE : These links are a tree, not a linked list */
	msi_dirent_new(msi, get_entry(msi, entry->leftSiblingID), parent, ds, dse);
	msi_dirent_new(msi, get_entry(msi, entry->rightSiblingID), parent, ds, dse);

	if (entry->type != DIR_STREAM) {
		msi_dirent_new(msi, get_entry(msi, entry->childID), dirent, ds, dse);
	}
	return dirent;
}

int msi_dirent_free(MSI_DIR_ENTRY *dirent)
{
	int i;

	if (dirent == NULL) {
		return 0;
	}
	for (i = 0; i < sk_MSI_DIR_ENTRY_num(dirent->children); i++) {
		MSI_DIR_ENTRY *child = sk_MSI_DIR_ENTRY_value(dirent->children, i);
		msi_dirent_free(child);
	}
	sk_MSI_DIR_ENTRY_free(dirent->children);
	OPENSSL_free(dirent->entry);
	OPENSSL_free(dirent);
	return 1;
}

/*
 * msi_prehash calculates the pre-hash used for 'MsiDigitalSignatureEx'
 * signatures in MSI files.  The pre-hash hashes only metadata (file names,
 * file sizes, creation times and modification times), whereas the basic
 * 'DigitalSignature' MSI signature only hashes file content.
 *
 * The hash is written to the hash BIO.
 */

/* Hash a MSI stream's extended metadata */
static void msi_prehash(MSI_FILE_ENTRY *entry, BIO *hash)
{
	if (entry->type != DIR_ROOT) {
		BIO_write(hash, entry->name, entry->nameLen - 2);
	}
	if (entry->type != DIR_STREAM) {
		BIO_write(hash, entry->clsid, sizeof(entry->clsid));
	} else {
		BIO_write(hash, entry->size, sizeof(entry->size)/2);
	}
	BIO_write(hash, entry->stateBits, sizeof(entry->stateBits));

	if (entry->type != DIR_ROOT) {
		BIO_write(hash, entry->creationTime, sizeof(entry->creationTime));
		BIO_write(hash, entry->modifiedTime, sizeof(entry->modifiedTime));
	}
}

/* Recursively hash a MSI directory's extended metadata */
int msi_prehash_dir(MSI_DIR_ENTRY *dirent, BIO *hash)
{
	int i, ret = 0;

	if (dirent == NULL) {
		goto out;
	}
	msi_prehash(dirent->entry, hash);
	if (!sk_MSI_DIR_ENTRY_is_sorted(dirent->children)) {
		sk_MSI_DIR_ENTRY_sort(dirent->children);
	}
	for (i = 0; i < sk_MSI_DIR_ENTRY_num(dirent->children); i++) {
		MSI_DIR_ENTRY *child = sk_MSI_DIR_ENTRY_value(dirent->children, i);
		if (!memcmp(child->name, digital_signature, sizeof(digital_signature))
				|| !memcmp(child->name, digital_signature_ex, sizeof(digital_signature_ex))) {
			continue;
		}
		if (child->type == DIR_STREAM) {
			msi_prehash(child->entry, hash);
		}
		if (child->type == DIR_STORAGE) {
			if (!msi_prehash_dir(child, hash)) {
				goto out;
			}
		}
	}
	ret = 1; /* OK */
out:
	return ret;
}

/* Recursively hash a MSI directory (storage) */
int msi_hash_dir(MSI_FILE *msi, MSI_DIR_ENTRY *parent, BIO *hash)
 {
	int i, ret = 0;

	if (!sk_MSI_DIR_ENTRY_is_sorted(parent->children)) {
		sk_MSI_DIR_ENTRY_sort(parent->children);
	}
	for (i = 0; i < sk_MSI_DIR_ENTRY_num(parent->children); i++) {
		MSI_DIR_ENTRY *child = sk_MSI_DIR_ENTRY_value(parent->children, i);
		if (!memcmp(child->name, digital_signature, sizeof(digital_signature))
				|| !memcmp(child->name, digital_signature_ex, sizeof(digital_signature_ex))) {
			continue;
		}
		if (child->type == DIR_STREAM) {
			uint32_t inlen = GET_UINT32_LE(child->entry->size);
			char *indata = (char *)OPENSSL_malloc(inlen);
			if (!msi_read_file(msi, child->entry, 0, indata, inlen)) {
				printf("Read stream data error\n\n");
				goto out;
			}
			if (BIO_write(hash, indata, inlen) <= 0) {
				printf("Write stream data error\n\n");
				goto out;
			}
			OPENSSL_free(indata);
		}
		if (child->type == DIR_STORAGE) {
			if (!msi_hash_dir(msi, child, hash)) {
				goto out;
			}
		}
	}
	BIO_write(hash, parent->entry->clsid, sizeof(parent->entry->clsid));
	ret = 1; /* OK */
out:
	return ret;
}

/* Compute a simple sha1/sha256 message digest of the MSI file */
void msi_calc_digest(char *indata, const EVP_MD *md, unsigned char *mdbuf, size_t fileend)
{
	BIO *bio = NULL;
	EVP_MD_CTX *mdctx;
	size_t n;

	bio = BIO_new_mem_buf(indata, fileend);
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit(mdctx, md);
	memset(mdbuf, 0, EVP_MAX_MD_SIZE);
	(void)BIO_seek(bio, 0);

	n = 0;
	while (n < fileend) {
		int l;
		static unsigned char bfb[16*1024*1024];
		size_t want = fileend - n;
		if (want > sizeof(bfb))
			want = sizeof(bfb);
		l = BIO_read(bio, bfb, want);
		if (l <= 0)
			break;
		EVP_DigestUpdate(mdctx, bfb, l);
		n += l;
	}
	EVP_DigestFinal(mdctx, mdbuf, NULL);
	EVP_MD_CTX_free(mdctx);
	BIO_free(bio);
}
