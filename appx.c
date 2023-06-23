/*
 * APPX file support library
 *
 * Copyright (C) 2023 Maciej Panek <maciej.panek_malpa_punxworks.com>
 *
 */

#define _FILE_OFFSET_BITS 64

#include "osslsigncode.h"
#include "helpers.h"

#include <zlib.h>
#include <inttypes.h>

#if defined(_MSC_VER)
#define fseeko _fseeki64
#define ftello _ftelli64
#endif

static const char PKZIP_LH_SIGNATURE[4] = { 'P', 'K', 3, 4 };
static const char PKZIP_CD_SIGNATURE[4] = { 'P', 'K', 1, 2 };
static const char PKZIP_EOCDR_SIGNATURE[4] = { 'P', 'K', 5, 6 };
static const char PKZIP_DATA_DESCRIPTOR_SIGNATURE[4] = { 'P', 'K', 7, 8 };
static const char PKZIP64_EOCD_LOCATOR_SIGNATURE[4] = { 'P', 'K', 6, 7 };
static const char PKZIP64_EOCDR_SIGNATURE[4] = { 'P', 'K', 6, 6 };
static const char *APP_SIGNATURE_FILENAME = "AppxSignature.p7x";
static const char *CONTENT_TYPES_FILENAME = "[Content_Types].xml";
static const char *BLOCK_MAP_FILENAME = "AppxBlockMap.xml";
static const char *APPXBUNDLE_MANIFEST_FILE_NAME = "AppxMetadata/AppxBundleManifest.xml";
static const char *CODE_INTEGRITY_FILENAME = "AppxMetadata/CodeIntegrity.cat";
static const char *SIGNATURE_CONTENT_TYPES_ENTRY = "<Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/>";
static const char *SIGNATURE_CONTENT_TYPES_CLOSING_TAG = "</Types>";
static const u_char APPX_UUID[] = { 0x4B, 0xDF, 0xC5, 0x0A, 0x07, 0xCE, 0xE2, 0x4D, 0xB7, 0x6E, 0x23, 0xC8, 0x39, 0xA0, 0x9F, 0xD1, };
static const u_char APPXBUNDLE_UUID[] = { 0xB3, 0x58, 0x5F, 0x0F, 0xDE, 0xAA, 0x9A, 0x4B, 0xA4, 0x34, 0x95, 0x74, 0x2D, 0x92, 0xEC, 0xEB, };

static const char PKCX_SIGNATURE[4] = { 'P', 'K', 'C', 'X' }; //Main header header
static const char APPX_SIGNATURE[4] = { 'A', 'P', 'P', 'X' }; //APPX header
static const char AXPC_SIGNATURE[4] = { 'A', 'X', 'P', 'C' }; //digest of zip file records
static const char AXCD_SIGNATURE[4] = { 'A', 'X', 'C', 'D' }; //digest zip file central directory
static const char AXCT_SIGNATURE[4] = { 'A', 'X', 'C', 'T' }; //digest of uncompressed [ContentTypes].xml
static const char AXBM_SIGNATURE[4] = { 'A', 'X', 'B', 'M' }; //digest of uncompressed AppxBlockMap.xml
static const char AXCI_SIGNATURE[4] = { 'A', 'X', 'C', 'I' }; //digest of uncompressed AppxMetadata/CodeIntegrity.cat (optional)

#define EOCDR_SIZE 22
#define ZIP64_EOCD_LOCATOR_SIZE 20
#define ZIP64_HEADER 0x01
#define COMPRESSION_NONE 0
#define COMPRESSION_DEFLATE 8
#define DATA_DESCRIPTOR_BIT (1 << 3)

typedef struct zipLocalHeader_s
{
	uint16_t version;
	uint16_t flags;
	uint16_t compression;
	uint16_t modTime;
	uint16_t modDate;
	uint32_t crc32;
	uint64_t compressedSize;
	uint64_t uncompressedSize;
	uint16_t fileNameLen;
	uint16_t extraFieldLen;
	char *fileName;
	uint8_t *extraField;

	bool compressedSizeInZip64;
	bool uncompressedSizeInZip64;
} zipLocalHeader_t;

typedef struct zipOverrideData_s
{
	uint32_t crc32;
	uint64_t compressedSize;
	uint64_t uncompressedSize;
	uint8_t *data;
} zipOverrideData_t;

typedef struct zipCentralDirectoryEntry_s
{
	uint16_t creatorVersion;
	uint16_t viewerVersion;
	uint16_t flags;
	uint16_t compression;
	uint16_t modTime;
	uint16_t modDate;
	uint32_t crc32;
	uint64_t compressedSize;
	uint64_t uncompressedSize;
	uint16_t fileNameLen;
	uint16_t extraFieldLen;
	uint16_t fileCommentLen;
	uint32_t diskNoStart;
	uint16_t internalAttr;
	uint32_t externalAttr;
	uint64_t offsetOfLocalHeader;
	char *fileName;
	uint8_t *extraField;
	char *fileComment;
	int64_t fileOffset;
	int64_t entryLen;

	bool compressedSizeInZip64;
	bool uncompressedSizeInZip64;
	bool offsetInZip64;
	bool diskNoInZip64;

	zipOverrideData_t *overrideData;

	struct zipCentralDirectoryEntry_s *next;
} zipCentralDirectoryEntry_t;

typedef struct zip64EOCDR_s
{
	uint64_t eocdrSize;
	uint16_t creatorVersion;
	uint16_t viewerVersion;
	uint32_t diskNumber;
	uint32_t diskWithCentralDirectory;
	uint64_t diskEntries;
	uint64_t totalEntries;
	uint64_t centralDirectorySize;
	uint64_t centralDirectoryOffset;
	int64_t commentLen;
	char *comment;
} zip64EOCDR_t;

typedef struct zip64EOCDLocator_s
{
	uint32_t diskWithEOCD;
	uint64_t eocdOffset;
	uint32_t totalNumberOfDisks;
} zip64EOCDLocator_t;

typedef struct zipEOCDR_s
{
	uint16_t diskNumber;
	uint16_t centralDirectoryDiskNumber;
	uint16_t diskEntries;
	uint16_t totalEntries;
	uint32_t centralDirectorySize;
	uint32_t centralDirectoryOffset;
	uint16_t commentLen;
	char *comment;
} zipEOCDR_t;

typedef struct zipFile_s
{
	FILE *f;
	zipCentralDirectoryEntry_t *centralDirectoryHead;
	uint64_t centralDirectorySize;
	uint64_t centralDirectoryOffset;
	uint64_t centralDirectoryRecordCount;
	int64_t eocdrOffset;
	int64_t eocdrLen;
	int64_t fileSize;
	bool isZip64;

	//this will come handy to rewrite the eocdr
	zipEOCDR_t eocdr;
	zip64EOCDLocator_t locator;
	zip64EOCDR_t eocdr64;
} zipFile_t;

uint8_t fileGetU8(FILE *f)
{
	uint8_t ret;
	fread(&ret, 1, 1, f);

	return ret;
}

uint16_t fileGetU16(FILE *f)
{
	uint8_t b[2];
	fread(b, 1, 2, f);

	uint16_t ret = b[1] << 8 | b[0];

	return ret;
}

uint32_t fileGetU32(FILE *f)
{
	uint8_t b[4];
	fread(b, 1, 4, f);

	uint32_t ret = b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0];

	return ret;
}

uint64_t fileGetU64(FILE *f)
{
	uint64_t l = fileGetU32(f);
	uint64_t h = fileGetU32(f);

	uint64_t ret = h << 32 | l;

	return ret;
}

uint8_t bufferGetU8(uint8_t *buffer, uint64_t *pos)
{
	uint8_t ret = buffer[*pos];
	*pos += 1;

	return ret;
}

uint16_t bufferGetU16(uint8_t *buffer, uint64_t *pos)
{
	uint16_t ret = buffer[*pos + 1] << 8 | buffer[*pos];
	*pos += 2;

	return ret;
}

uint32_t bufferGetU32(uint8_t *buffer, uint64_t *pos)
{
	uint32_t ret = buffer[*pos + 3] << 24 | buffer[*pos + 2] << 16 | buffer[*pos + 1] << 8 | buffer[*pos];

	*pos += 4;
	return ret;
}

uint64_t bufferGetU64(uint8_t *buffer, uint64_t *pos)
{
	uint64_t l = bufferGetU32(buffer, pos);
	uint64_t h = bufferGetU32(buffer, pos);

	uint64_t ret = h << 32 | l;

	return ret;
}

void bioAddU8(BIO *bio, uint8_t v)
{
	BIO_write(bio, &v, 1);
}

void bioAddU16(BIO *bio, uint16_t v)
{
	uint8_t b[2];

	b[0] = v & 0xFF;
	b[1] = (v >> 8) & 0xFF;

	BIO_write(bio, b, 2);
}

void bioAddU32(BIO *bio, uint32_t v)
{
	uint8_t b[4];

	b[0] = v & 0xFF;
	b[1] = (v >> 8) & 0xFF;
	b[2] = (v >> 16) & 0xFF;
	b[3] = (v >> 24) & 0xFF;

	BIO_write(bio, b, 4);
}

void bioAddU64(BIO *bio, uint64_t v)
{
	uint32_t l = v & 0xFFFFFFFF;
	uint32_t h = (v >> 32) & 0xFFFFFFFF;

	bioAddU32(bio, l);
	bioAddU32(bio, h);
}

bool readZipEOCDR(zipEOCDR_t *eocdr, FILE *f)
{
	char signature[4];

	fseeko(f, -EOCDR_SIZE, SEEK_END);

	int ret = fread(signature, 1, 4, f);

	if (memcmp(signature, PKZIP_EOCDR_SIGNATURE, 4))
	{
		printf("The input file is not a valip zip file - could not find End of Central Directory record\n");
		return false;
	}

	eocdr->diskNumber = fileGetU16(f);
	eocdr->centralDirectoryDiskNumber = fileGetU16(f);
	eocdr->diskEntries = fileGetU16(f);
	eocdr->totalEntries = fileGetU16(f);
	eocdr->centralDirectorySize = fileGetU32(f);
	eocdr->centralDirectoryOffset = fileGetU32(f);
	eocdr->commentLen = fileGetU16(f);

	/*if (eocdr->centralDirectoryDiskNumber > 1 || eocdr->diskNumber > 1 ||
		eocdr->centralDirectoryDiskNumber != eocdr->diskNumber ||
		eocdr->diskEntries != eocdr->totalEntries)
	{
		printf("The input file is a multipart archive - not supported\n");
		return false;
	}*/

	if (eocdr->commentLen > 0)
	{
		eocdr->comment = calloc(1, eocdr->commentLen + 1);
		fread(eocdr->comment, 1, eocdr->commentLen, f);
	}
	else
	{
		eocdr->comment = NULL;
	}

	return true;
}

bool readZip64EOCDLocator(zip64EOCDLocator_t *locator, FILE *f)
{
	char signature[4];

	fseeko(f, -(EOCDR_SIZE + ZIP64_EOCD_LOCATOR_SIZE), SEEK_END);

	fread(signature, 1, 4, f);

	if (memcmp(signature, PKZIP64_EOCD_LOCATOR_SIGNATURE, 4))
	{
		printf("The input file is not a valip zip file - could not find zip64 EOCD locator\n");
		return false;
	}

	locator->diskWithEOCD = fileGetU32(f);
	locator->eocdOffset = fileGetU64(f);
	locator->totalNumberOfDisks = fileGetU32(f);

	return true;
}

bool readZip64EOCDR(zip64EOCDR_t *eocdr, FILE *f, uint64_t offset)
{
	char signature[4];

	fseeko(f, offset, SEEK_SET);

	fread(signature, 1, 4, f);

	if (memcmp(signature, PKZIP64_EOCDR_SIGNATURE, 4))
	{
		printf("The input file is not a valip zip file - could not find zip64 End of Central Directory record\n");
		return NULL;
	}

	eocdr->eocdrSize = fileGetU64(f);
	eocdr->creatorVersion = fileGetU16(f);
	eocdr->viewerVersion = fileGetU16(f);
	eocdr->diskNumber = fileGetU32(f);
	eocdr->diskWithCentralDirectory = fileGetU32(f);
	eocdr->diskEntries = fileGetU64(f);
	eocdr->totalEntries = fileGetU64(f);
	eocdr->centralDirectorySize = fileGetU64(f);
	eocdr->centralDirectoryOffset = fileGetU64(f);
	eocdr->commentLen = eocdr->eocdrSize - 44;

	if (eocdr->commentLen > 0)
	{
		eocdr->comment = malloc(eocdr->commentLen);
		fread(eocdr->comment, 1, eocdr->commentLen, f);
	}

	if (eocdr->diskWithCentralDirectory > 1 || eocdr->diskNumber > 1 ||
		eocdr->diskWithCentralDirectory != eocdr->diskNumber ||
		eocdr->totalEntries != eocdr->diskEntries)
	{
		printf("The input file is a multipart archive - not supported\n");
		return false;
	}

	return true;
}

void freeZipCentralDirectoryEntry(zipCentralDirectoryEntry_t *entry)
{
	free(entry->fileName);
	free(entry->extraField);
	free(entry->fileComment);
	if (entry->overrideData)
	{
		free(entry->overrideData->data);
	}

	free(entry->overrideData);
	free(entry);
}

void freeZip(zipFile_t *zip)
{
	fclose(zip->f);

	free(zip->eocdr.comment);
	free(zip->eocdr64.comment);

	zipCentralDirectoryEntry_t *next = NULL;

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = next)
	{
		next = entry->next;
		freeZipCentralDirectoryEntry(entry);
	}

	free(zip);
}

zipCentralDirectoryEntry_t *zipGetCDEntryByName(zipFile_t *zip, const char *name)
{
	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		if (!strcmp(entry->fileName, name))
		{
			return entry;
		}
	}

	return NULL;
}

bool zipReadLocalHeader(zipLocalHeader_t *header, zipFile_t *zip, uint32_t compressedSize)
{
	char signature[4];

	FILE *f = zip->f;

	fread(signature, 1, 4, f);

	if (memcmp(signature, PKZIP_LH_SIGNATURE, 4))
	{
		printf("The input file is not a valip zip file - local header signature does not match\n");
		return false;
	}

	header->version = fileGetU16(f);
	header->flags = fileGetU16(f);
	header->compression = fileGetU16(f);
	header->modTime = fileGetU16(f);
	header->modDate = fileGetU16(f);
	header->crc32 = fileGetU32(f);
	header->compressedSize = fileGetU32(f);
	header->uncompressedSize = fileGetU32(f);
	header->fileNameLen = fileGetU16(f);
	header->extraFieldLen = fileGetU16(f);

	if (header->fileNameLen > 0)
	{
		header->fileName = calloc(1, header->fileNameLen + 1);
		fread(header->fileName, 1, header->fileNameLen, f);
	}
	else
	{
		header->fileName = NULL;
	}

	if (header->extraFieldLen > 0)
	{
		header->extraField = calloc(1, header->extraFieldLen);
		fread(header->extraField, 1, header->extraFieldLen, f);
	}
	else
	{
		header->extraField = NULL;
	}

	if (header->flags & DATA_DESCRIPTOR_BIT)
	{
		int64_t offset = ftello(f);
		fseeko(f, compressedSize, SEEK_CUR);
		fread(signature, 1, 4, f);
		
		if (memcmp(signature, PKZIP_DATA_DESCRIPTOR_SIGNATURE, 4))
		{
			printf("The input file is not a valip zip file - flags indicate data descriptor, but data descriptor signature does not match\n");
			
			free(header->fileName);
			free(header->extraField);

			return false;
		}
		
		header->crc32 = fileGetU32(f);
		if (zip->isZip64)
		{
			header->compressedSize = fileGetU64(f);
			header->uncompressedSize = fileGetU64(f);
		}
		else
		{
			header->compressedSize = fileGetU32(f);
			header->uncompressedSize = fileGetU32(f);
		}
	

		fseeko(f, offset, SEEK_SET);
	}

	if (header->uncompressedSize == 0xFFFFFFFFF || header->compressedSize == 0xFFFFFFFF)
	{
		if (header->extraFieldLen > 4)
		{
			uint64_t pos = 0;
			uint16_t op = bufferGetU16(header->extraField, &pos);

			if (op != ZIP64_HEADER)
			{
				printf("Expected zip64 header in local header extra field, got : 0x%X\n", op);
				free(header->fileName);
				free(header->extraField);
				header->fileName = NULL;
				header->extraField = NULL;

				return false;
			}

			uint16_t len = bufferGetU16(header->extraField, &pos);

			if (header->uncompressedSize == 0xFFFFFFFF)
			{
				if (len >= 8)
				{
					header->uncompressedSize = bufferGetU64(header->extraField, &pos);
					header->uncompressedSizeInZip64 = true;
				}
				else
				{
					printf("Invalid zip64 local header entry\n");
					free(header->fileName);
					free(header->extraField);
					header->fileName = NULL;
					header->extraField = NULL;

					return false;
				}
			}

			if (header->compressedSize == 0xFFFFFFFF)
			{
				if (len >= 16)
				{
					header->compressedSize = bufferGetU64(header->extraField, &pos);
					header->compressedSizeInZip64 = true;
				}
				else
				{
					printf("Invalid zip64 local header entry\n");
					free(header->fileName);
					free(header->extraField);
					header->fileName = NULL;
					header->extraField = NULL;

					return false;
				}
			}
		}
		else
		{
			free(header->fileName);
			free(header->extraField);
			header->fileName = NULL;
			header->extraField = NULL;

			return false;
		}
	}

	return true;
}

zipCentralDirectoryEntry_t *zipReadNextCentralDirectoryEntry(FILE *f)
{
	char signature[4];

	fread(signature, 1, 4, f);

	if (memcmp(signature, PKZIP_CD_SIGNATURE, 4))
	{
		printf("The input file is not a valip zip file - could not find Central Directory record\n");
		return NULL;
	}

	zipCentralDirectoryEntry_t *entry = calloc(1, sizeof(zipCentralDirectoryEntry_t));

	entry->fileOffset = ftello(f) - 4;
	entry->creatorVersion = fileGetU16(f);
	entry->viewerVersion = fileGetU16(f);
	entry->flags = fileGetU16(f);
	entry->compression = fileGetU16(f);
	entry->modTime = fileGetU16(f);
	entry->modDate = fileGetU16(f);
	entry->crc32 = fileGetU32(f);
	entry->compressedSize = fileGetU32(f);
	entry->uncompressedSize = fileGetU32(f);
	entry->fileNameLen = fileGetU16(f);
	entry->extraFieldLen = fileGetU16(f);
	entry->fileCommentLen = fileGetU16(f);
	entry->diskNoStart = fileGetU16(f);
	entry->internalAttr = fileGetU16(f);
	entry->externalAttr = fileGetU32(f);
	entry->offsetOfLocalHeader = fileGetU32(f);

	if (entry->fileNameLen > 0)
	{
		entry->fileName = calloc(1, entry->fileNameLen + 1);
		fread(entry->fileName, 1, entry->fileNameLen, f);
	}

	if (entry->extraFieldLen > 0)
	{
		entry->extraField = calloc(1, entry->extraFieldLen);
		fread(entry->extraField, 1, entry->extraFieldLen, f);
	}

	if (entry->fileCommentLen > 0)
	{
		entry->fileComment = calloc(1, entry->fileCommentLen + 1);
		fread(entry->fileComment, 1, entry->fileCommentLen, f);
	}

	if (entry->uncompressedSize == 0xFFFFFFFFF || entry->compressedSize == 0xFFFFFFFF ||
		entry->offsetOfLocalHeader == 0xFFFFFFFF || entry->diskNoStart == 0xFFFF)
	{
		if (entry->extraFieldLen > 4)
		{
			uint64_t pos = 0;
			uint16_t header = bufferGetU16(entry->extraField, &pos);

			if (header != ZIP64_HEADER)
			{
				printf("Expected zip64 header in central directory extra field, got : 0x%X\n", header);
				freeZipCentralDirectoryEntry(entry);
				return NULL;
			}

			uint64_t len = bufferGetU16(entry->extraField, &pos);

			if (entry->uncompressedSize == 0xFFFFFFFF)
			{
				if (len >= 8)
				{
					entry->uncompressedSize = bufferGetU64(entry->extraField, &pos);
					entry->uncompressedSizeInZip64 = true;
				}
				else
				{
					printf("Invalid zip64 central directory entry\n");
					freeZipCentralDirectoryEntry(entry);
					return NULL;
				}
			}

			if (entry->compressedSize == 0xFFFFFFFF)
			{
				if (len >= 16)
				{
					entry->compressedSize = bufferGetU64(entry->extraField, &pos);
					entry->compressedSizeInZip64 = true;
				}
				else
				{
					printf("Invalid zip64 central directory entry\n");
					freeZipCentralDirectoryEntry(entry);
					return NULL;
				}
			}

			if (entry->offsetOfLocalHeader == 0xFFFFFFFF)
			{
				if (len >= 24)
				{
					entry->offsetOfLocalHeader = bufferGetU64(entry->extraField, &pos);
					entry->offsetInZip64 = true;
				}
				else
				{
					printf("Invalid zip64 central directory entry\n");
					freeZipCentralDirectoryEntry(entry);
					return NULL;
				}
			}

			if (entry->diskNoStart == 0xFFFF)
			{
				if (len >= 28)
				{
					entry->diskNoStart = bufferGetU32(entry->extraField, &pos);
					entry->diskNoInZip64 = true;
				}
				else
				{
					printf("Invalid zip64 central directory entry\n");
					freeZipCentralDirectoryEntry(entry);
					return NULL;
				}
			}
		}
		else
		{
			freeZipCentralDirectoryEntry(entry);
			return NULL;
		}
	}

	entry->entryLen = ftello(f) - entry->fileOffset;

	return entry;
}

bool zipReadCentralDirectory(zipFile_t *zip, FILE *f)
{
	fseeko(f, zip->centralDirectoryOffset, SEEK_SET);

	zipCentralDirectoryEntry_t *prev = NULL;

	for (uint64_t i = 0; i < zip->centralDirectoryRecordCount; i++)
	{
		zipCentralDirectoryEntry_t *entry = zipReadNextCentralDirectoryEntry(f);

		if (!entry)
		{
			return false;
		}

		if (prev)
		{
			prev->next = entry;
		}

		if (!zip->centralDirectoryHead)
		{
			zip->centralDirectoryHead = entry;
		}

		prev = entry;
	}

	return true;
}

void zipPrintCentralDirectory(zipFile_t *zip)
{
	printf("Central directory entry count: %" PRIu64"\n", zip->centralDirectoryRecordCount);

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		printf("Name: %s Compressed: %" PRIu64" Uncompressed: %" PRIu64" Offset: %" PRIu64"\n", entry->fileName,
			entry->compressedSize, entry->uncompressedSize, entry->offsetOfLocalHeader);
	}
}

int zipInflate(Bytef *dest, uLongf *destLen, const Bytef *source, uLong *sourceLen)
{
	z_stream stream;
	int err;
	const uInt max = (uInt)-1;
	uLong len, left;
	Byte buf[1];    /* for detection of incomplete stream when *destLen == 0 */

	len = *sourceLen;
	if (*destLen)
	{
		left = *destLen;
		*destLen = 0;
	}
	else
	{
		left = 1;
		dest = buf;
	}

	stream.next_in = (z_const Bytef *)source;
	stream.avail_in = 0;
	stream.zalloc = (alloc_func)0;
	stream.zfree = (free_func)0;
	stream.opaque = (voidpf)0;

	err = inflateInit2(&stream, -MAX_WBITS);
	if (err != Z_OK) return err;

	stream.next_out = dest;
	stream.avail_out = 0;

	do
	{
		if (stream.avail_out == 0)
		{
			stream.avail_out = left > (uLong)max ? max : (uInt)left;
			left -= stream.avail_out;
		}

		if (stream.avail_in == 0)
		{
			stream.avail_in = len > (uLong)max ? max : (uInt)len;
			len -= stream.avail_in;
		}

		err = inflate(&stream, Z_NO_FLUSH);
	} while (err == Z_OK);

	*sourceLen -= len + stream.avail_in;
	
	if (dest != buf)
	{
		*destLen = stream.total_out;
	}
	else if (stream.total_out && err == Z_BUF_ERROR)
	{
		left = 1;
	}

	inflateEnd(&stream);

	return err == Z_STREAM_END ? Z_OK :
		err == Z_NEED_DICT ? Z_DATA_ERROR :
		err == Z_BUF_ERROR && left + stream.avail_out ? Z_DATA_ERROR :
		err;
}

int zipDeflate(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level)
{
	z_stream stream;
	int err;
	const uInt max = (uInt)-1;
	uLong left;

	left = *destLen;
	*destLen = 0;

	stream.zalloc = (alloc_func)0;
	stream.zfree = (free_func)0;
	stream.opaque = (voidpf)0;

	err = deflateInit2(&stream, level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
	if (err != Z_OK) return err;

	stream.next_out = dest;
	stream.avail_out = 0;
	stream.next_in = (z_const Bytef *)source;
	stream.avail_in = 0;

	do {
		if (stream.avail_out == 0)
		{
			stream.avail_out = left > (uLong)max ? max : (uInt)left;
			left -= stream.avail_out;
		}
		if (stream.avail_in == 0)
		{
			stream.avail_in = sourceLen > (uLong)max ? max : (uInt)sourceLen;
			sourceLen -= stream.avail_in;
		}
		err = deflate(&stream, sourceLen ? Z_NO_FLUSH : Z_FINISH);
	} while (err == Z_OK);

	//deflate(&stream, Z_SYNC_FLUSH);

	*destLen = stream.total_out;
	deflateEnd(&stream);
	return err == Z_STREAM_END ? Z_OK : err;
}

bool zipReadFileData(zipFile_t *zip, zipCentralDirectoryEntry_t *entry, uint8_t **pData, uint64_t *dataSize, bool unpack)
{
	FILE *f = zip->f;
	fseeko(f, entry->offsetOfLocalHeader, SEEK_SET);

	uint8_t *compressedData = NULL;
	uint64_t compressedSize = 0;
	uint64_t uncompressedSize = 0;

	if (entry->overrideData)
	{
		compressedSize = entry->overrideData->compressedSize;
		uncompressedSize = entry->overrideData->uncompressedSize;
		compressedData = malloc(compressedSize);
		memcpy(compressedData, entry->overrideData->data, compressedSize);
	}
	else
	{
		zipLocalHeader_t header;

		memset(&header, 0, sizeof(header));

		if (!zipReadLocalHeader(&header, zip, entry->compressedSize))
		{
			return false;
		}

		if (strcmp(header.fileName, entry->fileName) || header.compressedSize != entry->compressedSize
			|| header.uncompressedSize != entry->uncompressedSize || header.compression != entry->compression)
		{
			printf("Local header does not match central directory entry\n");
			return false;
		}

		//we don't really need those
		free(header.fileName);
		free(header.extraField);

		compressedData = malloc(entry->compressedSize);

		fread(compressedData, 1, entry->compressedSize, f);

		compressedSize = entry->compressedSize;
		uncompressedSize = entry->uncompressedSize;
	}

	if (!unpack || unpack && entry->compression == COMPRESSION_NONE)
	{
		*pData = compressedData;
		*dataSize = compressedSize;
	}
	else if (entry->compression == COMPRESSION_DEFLATE)
	{
		uint8_t *uncompressedData = malloc(uncompressedSize);
		uLongf destLen = uncompressedSize;
		uLongf sourceLen = compressedSize;

		int ret = zipInflate(uncompressedData, &destLen, compressedData, &sourceLen);

		free(compressedData);

		if (ret != Z_OK)
		{
			printf("data decompresssion failed, zlib error: %d\n", ret);

			free(uncompressedData);

			return false;
		}
		else
		{
			*pData = uncompressedData;
			*dataSize = destLen;
		}
	}
	else
	{
		printf("Unsupported compression mode: %d\n", entry->compression);
		free(compressedData);
		return false;
	}

	return true;
}

void zipWriteLocalHeader(BIO *bio, zipLocalHeader_t *header, uint64_t *sizeonDisk)
{
	BIO_write(bio, PKZIP_LH_SIGNATURE, 4);

	bioAddU16(bio, header->version);
	bioAddU16(bio, header->flags);
	bioAddU16(bio, header->compression);
	bioAddU16(bio, header->modTime);
	bioAddU16(bio, header->modDate);

	if (header->flags & DATA_DESCRIPTOR_BIT)
	{
		bioAddU32(bio, 0);
		bioAddU32(bio, 0);
		bioAddU32(bio, 0);
	}
	else
	{
		bioAddU32(bio, header->crc32);
		bioAddU32(bio, header->compressedSizeInZip64 ? 0xFFFFFFFF :  header->compressedSize);
		bioAddU32(bio, header->uncompressedSizeInZip64 ? 0xFFFFFFFF : header->uncompressedSize);
	}

	bioAddU16(bio, header->fileNameLen);
	bioAddU16(bio, header->extraFieldLen);

	if (header->fileNameLen > 0)
	{
		BIO_write(bio, header->fileName, header->fileNameLen);
	}

	if (header->extraFieldLen > 0)
	{
		BIO_write(bio, header->extraField, header->extraFieldLen);
	}

	*sizeonDisk = 30 + header->fileNameLen + header->extraFieldLen;
}

void zipWriteCentralDirectoryEntry(BIO *bio, zipCentralDirectoryEntry_t *entry, int64_t offsetDiff, uint64_t *sizeOnDisk)
{
	BIO_write(bio, PKZIP_CD_SIGNATURE, 4);
	bioAddU16(bio, entry->creatorVersion);
	bioAddU16(bio, entry->viewerVersion);
	bioAddU16(bio, entry->flags);
	bioAddU16(bio, entry->compression);
	bioAddU16(bio, entry->modTime);
	bioAddU16(bio, entry->modDate);
	bioAddU32(bio, entry->overrideData ? entry->overrideData->crc32 : entry->crc32);
	bioAddU32(bio, entry->compressedSizeInZip64 ? 0xFFFFFFFF : entry->overrideData ? entry->overrideData->compressedSize : entry->compressedSize);
	bioAddU32(bio, entry->uncompressedSizeInZip64 ? 0xFFFFFFFF : entry->overrideData ? entry->overrideData->uncompressedSize : entry->uncompressedSize);
	bioAddU16(bio, entry->fileNameLen);
	bioAddU16(bio, entry->extraFieldLen);
	bioAddU16(bio, entry->fileCommentLen);
	bioAddU16(bio, entry->diskNoInZip64 ? 0xFFFF : entry->diskNoStart);
	bioAddU16(bio, entry->internalAttr);
	bioAddU32(bio, entry->externalAttr);
	bioAddU32(bio, entry->offsetInZip64 ? 0xFFFFFFFF : entry->offsetOfLocalHeader + offsetDiff);

	if (entry->fileNameLen > 0 && entry->fileName)
	{
		BIO_write(bio, entry->fileName, entry->fileNameLen);
	}

	int zip64ChunkSize = 0;
	if (entry->uncompressedSizeInZip64) zip64ChunkSize += 8;
	if (entry->compressedSizeInZip64) zip64ChunkSize += 8;
	if (entry->offsetInZip64) zip64ChunkSize += 8;
	if (entry->diskNoInZip64) zip64ChunkSize += 4;

	if (zip64ChunkSize > 0)
	{
		bioAddU16(bio, ZIP64_HEADER);
		bioAddU16(bio, zip64ChunkSize);

		if (entry->uncompressedSizeInZip64) bioAddU64(bio, entry->overrideData ? entry->overrideData->uncompressedSize : entry->uncompressedSize);
		if (entry->compressedSizeInZip64) bioAddU64(bio, entry->overrideData ? entry->overrideData->compressedSize : entry->compressedSize);
		if (entry->offsetInZip64) bioAddU64(bio, entry->offsetOfLocalHeader + offsetDiff);
		if (entry->diskNoInZip64) bioAddU32(bio, entry->diskNoStart);
	}

	//if (entry->extraFieldLen > 0 && entry->extraField)
	//{
	//	//todo, if override daata, need to rewrite the extra field
	//	BIO_write(bio, entry->extraField, entry->extraFieldLen);
	//}

	if (entry->fileCommentLen > 0 && entry->fileComment)
	{
		BIO_write(bio, entry->fileComment, entry->fileCommentLen);
	}

	*sizeOnDisk = 46 + entry->fileNameLen + entry->extraFieldLen + entry->fileCommentLen;
}

bool zipAppendFile(zipFile_t *zip, BIO *bio, const char *fn, uint8_t *data, uint64_t dataSize, bool comprs)
{
	zipLocalHeader_t header;
	memset(&header, 0, sizeof(zipLocalHeader_t));

	time_t tim;
	struct tm *timeinfo;

	uint8_t *dataToWrite = data;
	uint64_t sizeToWrite = dataSize;

	if (comprs)
	{
		dataToWrite = malloc(dataSize);
		uLongf destLen = dataSize;

		int ret = zipDeflate(dataToWrite, &destLen, data, dataSize, 8);
		if (ret != Z_OK)
		{
			printf("Zip deflate failed: %d\n", ret);
			free(dataToWrite);

			return false;
		}

		sizeToWrite = destLen;
	}

	time(&tim);
	timeinfo = localtime(&tim);

	header.version = 0x14;
	header.flags = 0;
	header.compression = comprs ? COMPRESSION_DEFLATE : 0;
	header.modTime = timeinfo->tm_hour << 11 | timeinfo->tm_min << 5 | timeinfo->tm_sec >> 1;
	header.modDate = (timeinfo->tm_year - 80) << 9 | (timeinfo->tm_mon + 1) << 5 | timeinfo->tm_mday;

	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, data, dataSize);

	header.crc32 = crc;
	header.uncompressedSize = dataSize;
	header.compressedSize = sizeToWrite;
	header.fileNameLen = strlen(fn);
	//this will be reassigned to CD entry and freed there
	header.fileName = calloc(1, header.fileNameLen + 1);
	memcpy(header.fileName, fn, header.fileNameLen);
	header.extraField = NULL;
	header.extraFieldLen = 0;

	uint64_t offset = BIO_tell(bio); //unfortunately BIO has no 64bit API, so we are limited to 2G files...
	//should probably rewrite it with using stdio and ftello64

	uint64_t dummy = 0;
	zipWriteLocalHeader(bio, &header, &dummy);

	uint64_t written = 0;

	while (sizeToWrite > 0)
	{
		uint64_t toWrite = sizeToWrite < SIZE_64K ? sizeToWrite : SIZE_64K;

		BIO_write(bio, dataToWrite + written, toWrite);

		sizeToWrite -= toWrite;
		written += toWrite;
	}

	if (comprs)
	{
		free(dataToWrite);
	}

	zipCentralDirectoryEntry_t *entry = calloc(1, sizeof(zipCentralDirectoryEntry_t));
	entry->creatorVersion = 0x2D;
	entry->viewerVersion = header.version;
	entry->flags = header.flags;
	entry->compression = header.compression;
	entry->modTime = header.modTime;
	entry->modDate = header.modDate;
	entry->crc32 = header.crc32;
	entry->uncompressedSize = header.uncompressedSize;
	entry->compressedSize = header.compressedSize;
	entry->fileName = header.fileName; //take ownership of the fileName pointer
	entry->fileNameLen = header.fileNameLen;
	entry->extraField = header.extraField;
	entry->extraFieldLen = header.extraFieldLen;
	entry->fileCommentLen = 0;
	entry->fileComment = NULL;
	entry->diskNoStart = 0;
	entry->offsetOfLocalHeader = offset;
	entry->next = NULL;
	entry->entryLen = entry->fileNameLen + entry->extraFieldLen + entry->fileCommentLen + 46;

	if (!zip->centralDirectoryHead)
	{
		zip->centralDirectoryHead = entry;
	}
	else
	{
		zipCentralDirectoryEntry_t *last = zip->centralDirectoryHead;

		while (last->next)
		{
			last = last->next;
		}

		last->next = entry;
	}

	return true;
}

bool zipOverrideFileData(zipFile_t *zip, zipCentralDirectoryEntry_t *entry, uint8_t *data, uint64_t dataSize, bool comprs)
{
	if (entry->overrideData)
	{
		free(entry->overrideData);
		free(entry->overrideData->data);
		entry->overrideData = NULL;
	}

	entry->overrideData = malloc(sizeof(zipOverrideData_t));
	entry->overrideData->data = malloc(dataSize);

	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, data, dataSize);
	entry->overrideData->crc32 = crc;
	entry->overrideData->uncompressedSize = dataSize;

	if (comprs)
	{
		uLongf destLen = dataSize;

		int ret = zipDeflate(entry->overrideData->data, &destLen, data, dataSize, 8);
		if (ret != Z_OK)
		{
			printf("Zip deflate failed: %d\n", ret);

			return false;
		}

		entry->overrideData->compressedSize = destLen;
	}
	else
	{
		memcpy(entry->overrideData, data, dataSize);
		entry->overrideData->compressedSize = dataSize;
	}

	return true;
}

bool zipRewriteData(zipFile_t *zip, zipCentralDirectoryEntry_t *entry, BIO *bio, uint64_t *sizeOnDisk)
{
	zipLocalHeader_t header;

	memset(&header, 0, sizeof(header));

	fseeko(zip->f, entry->offsetOfLocalHeader, SEEK_SET);

	if (!zipReadLocalHeader(&header, zip, entry->compressedSize))
	{
		return false;
	}

	if (entry->overrideData)
	{
		header.compressedSize = entry->overrideData->compressedSize;
		header.uncompressedSize = entry->overrideData->uncompressedSize;
		header.crc32 = entry->overrideData->crc32;
	}

	zipWriteLocalHeader(bio, &header, sizeOnDisk);

	uint8_t *data = NULL;

	if (entry->overrideData)
	{
		BIO_write(bio, entry->overrideData->data, entry->overrideData->compressedSize);
		fseeko(zip->f, entry->compressedSize, SEEK_CUR);

		*sizeOnDisk += entry->overrideData->compressedSize;
	}
	else
	{
		uint64_t len = entry->compressedSize;

		data = malloc(SIZE_64K);

		while (len > 0)
		{
			uint64_t toWrite = len < SIZE_64K ? len : SIZE_64K;

			fread(data, 1, toWrite, zip->f);
			BIO_write(bio, data, toWrite);

			*sizeOnDisk += toWrite;

			len -= toWrite;
		}
	}

	if (header.flags & DATA_DESCRIPTOR_BIT)
	{
		BIO_write(bio, PKZIP_DATA_DESCRIPTOR_SIGNATURE, 4);

		bioAddU32(bio, header.crc32);

		if (zip->isZip64)
		{
			bioAddU64(bio, header.compressedSize);
			bioAddU64(bio, header.uncompressedSize);
		}
		else
		{
			bioAddU32(bio, header.compressedSize);
			bioAddU32(bio, header.uncompressedSize);
		}

		if (zip->isZip64)
		{
			fseeko(zip->f, 24, SEEK_CUR);
			*sizeOnDisk += 24;
		}
		else
		{
			fseeko(zip->f, 16, SEEK_CUR);
			*sizeOnDisk += 16;
		}
	}

	free(data);
	free(header.fileName);
	free(header.extraField);

	return true;
}

bool zipReadFileDataByName(zipFile_t *zip, const char *name, uint8_t **pData, uint64_t *dataSize, bool unpack)
{
	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		if (!strcmp(name, entry->fileName))
		{
			return zipReadFileData(zip, entry, pData, dataSize, unpack);
		}
	}

	return false;
}

bool zipEntryExist(zipFile_t *zip, const char *name)
{
	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		if (!strcmp(name, entry->fileName))
		{
			return true;
		}
	}

	return false;
}

uint8_t *zipCalcDigest(zipFile_t *zip, const char *fileName, bool unpack, const EVP_MD *md)
{
	uint8_t *data = NULL;
	uint64_t dataSize = 0;

	if (!zipReadFileDataByName(zip, fileName, &data, &dataSize, true))
	{
		return NULL;
	}

	size_t written;
	uint32_t idx = 0, fileend;
	u_char *mdbuf = NULL;

	BIO *bhash = BIO_new(BIO_f_md());

	if (!BIO_set_md(bhash, md))
	{
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}

	BIO_push(bhash, BIO_new(BIO_s_null()));

	if (!bio_hash_data(bhash, data, 0, dataSize))
	{
		free(data);
		BIO_free_all(bhash);
		return NULL;
	}

	mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);

	free(data);

	return mdbuf;
}

zipFile_t *openZip(const char *fn)
{
	FILE *f = fopen(fn, "rb");

	if (!f)
	{
		return NULL;
	}

	char signature[4];

	//oncde we read eocdr, comment might be allocated and we need to take care of it -> create the zipFile structure
	zipFile_t *zip = calloc(1, sizeof(zipFile_t));
	zip->f = f;

	if (!readZipEOCDR(&zip->eocdr, f))
	{
		freeZip(zip);
		fclose(f);
		return NULL;
	}

	fseeko(f, 0, SEEK_END);
	zip->fileSize = ftello(f);

	if (zip->eocdr.centralDirectoryOffset == 0xFFFFFFFF || zip->eocdr.centralDirectorySize == 0xFFFFFFFF)
	{
		//probably a zip64 file
		if (!readZip64EOCDLocator(&zip->locator, f))
		{
			freeZip(zip);
			return NULL;
		}

		if (!readZip64EOCDR(&zip->eocdr64, f, zip->locator.eocdOffset))
		{
			freeZip(zip);
			return NULL;
		}

		zip->isZip64 = true;

		zip->eocdrOffset = zip->locator.eocdOffset;
		zip->eocdrLen = zip->fileSize - zip->eocdrOffset;

		zip->centralDirectoryOffset = zip->eocdr64.centralDirectoryOffset;
		zip->centralDirectorySize = zip->eocdr64.centralDirectorySize;
		zip->centralDirectoryRecordCount = zip->eocdr64.totalEntries;
	}
	else
	{

		zip->eocdrOffset = zip->fileSize - EOCDR_SIZE;
		zip->eocdrLen = EOCDR_SIZE;
		zip->centralDirectoryOffset = zip->eocdr.centralDirectoryOffset;
		zip->centralDirectorySize = zip->eocdr.centralDirectorySize;
		zip->centralDirectoryRecordCount = zip->eocdr.totalEntries;
	}

	if (!zipReadCentralDirectory(zip, f))
	{
		freeZip(zip);
		return NULL;
	}

	return zip;
}

/*****************************************************/

typedef struct {
	ASN1_INTEGER *a;
	ASN1_OCTET_STRING *string;
	ASN1_INTEGER *b;
	ASN1_INTEGER *c;
	ASN1_INTEGER *d;
	ASN1_INTEGER *e;
	ASN1_INTEGER *f;
} AppxSpcSipInfo;

DECLARE_ASN1_FUNCTIONS(AppxSpcSipInfo)

ASN1_SEQUENCE(AppxSpcSipInfo) = {
	ASN1_SIMPLE(AppxSpcSipInfo, a, ASN1_INTEGER),
	ASN1_SIMPLE(AppxSpcSipInfo, string, ASN1_OCTET_STRING),
	ASN1_SIMPLE(AppxSpcSipInfo, b, ASN1_INTEGER),
	ASN1_SIMPLE(AppxSpcSipInfo, c, ASN1_INTEGER),
	ASN1_SIMPLE(AppxSpcSipInfo, d, ASN1_INTEGER),
	ASN1_SIMPLE(AppxSpcSipInfo, e, ASN1_INTEGER),
	ASN1_SIMPLE(AppxSpcSipInfo, f, ASN1_INTEGER),
} ASN1_SEQUENCE_END(AppxSpcSipInfo)

IMPLEMENT_ASN1_FUNCTIONS(AppxSpcSipInfo)

struct appx_ctx_st
{
	zipFile_t *zip;
	uint8_t *calculatedBMHash;
	uint8_t *calculatedCTHash;
	uint8_t *calculatedCDHash;
	uint8_t *calculatedDataHash;
	uint8_t *calculatedCIHash;
	uint8_t *existingBMHash;
	uint8_t *existingCTHash;
	uint8_t *existingCDHash;
	uint8_t *existingDataHash;
	uint8_t *existingCIHash;
	bool isBundle;
} appx_ctx_t;

/* FILE_FORMAT method prototypes */
/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *appx_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static ASN1_OBJECT *appx_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static int appx_check_file(FILE_FORMAT_CTX *ctx, int detached);
static int appx_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *appx_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static int appx_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *appx_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int appx_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *appx_bio_free(BIO *hash, BIO *outdata);
static void appx_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_appx = {
    .ctx_new = appx_ctx_new,
	.data_blob_get = appx_spc_sip_info_get,
    .check_file = appx_check_file,
    .verify_digests = appx_verify_digests,
    .pkcs7_extract = appx_pkcs7_extract,
    .remove_pkcs7 = appx_remove_pkcs7,
    .pkcs7_prepare = appx_pkcs7_prepare,
    .append_pkcs7 = appx_append_pkcs7,
    .bio_free = appx_bio_free,
    .ctx_cleanup = appx_ctx_cleanup,
};

FILE_FORMAT_CTX *appx_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
	zipFile_t *zip = openZip(options->infile);

	if (!zip)
	{
		return NULL;
	}

	if (options->verbose)
	{
		zipPrintCentralDirectory(zip);
	}

	FILE_FORMAT_CTX *ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
	ctx->appx_ctx = OPENSSL_zalloc(sizeof(appx_ctx_t));

	ctx->appx_ctx->zip = zip;
	ctx->format = &file_format_appx;
	ctx->options = options;

	if (zipGetCDEntryByName(zip, APPXBUNDLE_MANIFEST_FILE_NAME))
	{
		ctx->appx_ctx->isBundle = true;
	}

	return ctx;
}

uint8_t *appx_calc_zip_data_hash(zipFile_t *zip, const EVP_MD *md, uint64_t *cdOffset)
{
	u_char *mdbuf = NULL;

	BIO *bhash = BIO_new(BIO_f_md());

	if (!BIO_set_md(bhash, md))
	{
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}

	BIO_push(bhash, BIO_new(BIO_s_null()));

	*cdOffset = 0;

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		//the signature file is considered not existent for hashing purposes
		if (!strcmp(entry->fileName, APP_SIGNATURE_FILENAME))
		{
			continue;
		}

		uint64_t sizeOnDisk = 0;
		if (!zipRewriteData(zip, entry, bhash, &sizeOnDisk))
		{
			printf("Rewrite data error\n");
			return false;
		}

		*cdOffset += sizeOnDisk;
	}

	mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);

	return mdbuf;
}

void appx_write_central_directory(zipFile_t *zip, BIO *bio, bool removeSignature, uint64_t cdOffset)
{
	int64_t offsetDiff = 0;
	uint64_t cdSize = 0;
	int noEntries = 0;

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		//the signature file is considered non existent for hashing purposes
		if (removeSignature && !strcmp(entry->fileName, APP_SIGNATURE_FILENAME))
		{
			continue;
		}

		uint64_t sizeOnDisk = 0;

		//APP_SIGNATURE is nt 'tainted' by offset shift after replacing the contents of [content_types]
		zipWriteCentralDirectoryEntry(bio, entry, strcmp(entry->fileName, APP_SIGNATURE_FILENAME) ? offsetDiff : 0, &sizeOnDisk);

		cdSize += sizeOnDisk;

		if (entry->overrideData)
		{
			offsetDiff += entry->overrideData->compressedSize - entry->compressedSize;
		}

		noEntries++;
	}

	if (zip->isZip64)
	{
		//eocdr
		BIO_write(bio, PKZIP64_EOCDR_SIGNATURE, 4);
		bioAddU64(bio, zip->eocdr64.eocdrSize);
		bioAddU16(bio, zip->eocdr64.creatorVersion);
		bioAddU16(bio, zip->eocdr64.viewerVersion);
		bioAddU32(bio, zip->eocdr64.diskNumber);
		bioAddU32(bio, zip->eocdr64.diskWithCentralDirectory);
		bioAddU64(bio, noEntries);
		bioAddU64(bio, noEntries);
		bioAddU64(bio, cdSize);
		bioAddU64(bio, cdOffset);

		if (zip->eocdr64.commentLen > 0)
		{
			BIO_write(bio, zip->eocdr64.comment, zip->eocdr64.commentLen);
		}

		//eocdr locator
		BIO_write(bio, PKZIP64_EOCD_LOCATOR_SIGNATURE, 4);
		bioAddU32(bio, zip->locator.diskWithEOCD);
		bioAddU64(bio, cdOffset + cdSize);

		bioAddU32(bio, zip->locator.totalNumberOfDisks);
	}

	BIO_write(bio, PKZIP_EOCDR_SIGNATURE, 4);
	//those need to be 0s even though packaging tool writes FFFFs here
	//it will fail verification if not zeros
	bioAddU16(bio, 0);
	bioAddU16(bio, 0);

	if (zip->eocdr.diskEntries != 0xFFFF)
	{
		bioAddU16(bio, noEntries);
	}
	else
	{
		bioAddU16(bio, 0xFFFF);
	}

	if (zip->eocdr.totalEntries != 0xFFFF)
	{
		bioAddU16(bio, noEntries);
	}
	else
	{
		bioAddU16(bio, 0xFFFF);
	}

	if (zip->eocdr.centralDirectorySize != 0xFFFFFFFF)
	{
		bioAddU32(bio, cdSize);
	}
	else
	{
		bioAddU32(bio, 0xFFFFFFFF);
	}

	if (zip->eocdr.centralDirectoryOffset != 0xFFFFFFFF)
	{
		bioAddU32(bio, cdOffset);
	}
	else
	{
		bioAddU32(bio, 0xFFFFFFFF);
	}

	bioAddU16(bio, zip->eocdr.commentLen);

	if (zip->eocdr.commentLen > 0)
	{
		BIO_write(bio, zip->eocdr.comment, zip->eocdr.commentLen);
	}
}

uint8_t *appx_calc_zip_central_directory_hash(zipFile_t *zip, const EVP_MD *md, uint64_t cdOffset)
{
	u_char *mdbuf = NULL;

	BIO *bhash = BIO_new(BIO_f_md());

	if (!BIO_set_md(bhash, md))
	{
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}

	BIO_push(bhash, BIO_new(BIO_s_null()));

	appx_write_central_directory(zip, bhash, true, cdOffset);

	mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);

	return mdbuf;
}

int appx_calculate_hashes(FILE_FORMAT_CTX *ctx)
{
	OPENSSL_free(ctx->appx_ctx->calculatedBMHash);
	OPENSSL_free(ctx->appx_ctx->calculatedCTHash);
	OPENSSL_free(ctx->appx_ctx->calculatedCDHash);
	OPENSSL_free(ctx->appx_ctx->calculatedDataHash);
	OPENSSL_free(ctx->appx_ctx->calculatedCIHash);

	ctx->appx_ctx->calculatedBMHash = NULL;
	ctx->appx_ctx->calculatedCIHash = NULL;
	ctx->appx_ctx->calculatedBMHash = NULL;
	ctx->appx_ctx->calculatedDataHash = NULL;
	ctx->appx_ctx->calculatedCIHash = NULL;

	ctx->appx_ctx->calculatedBMHash = zipCalcDigest(ctx->appx_ctx->zip, BLOCK_MAP_FILENAME, true, EVP_sha256());
	ctx->appx_ctx->calculatedCTHash = zipCalcDigest(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME, true, EVP_sha256());

	uint64_t cdOffset;

	ctx->appx_ctx->calculatedDataHash = appx_calc_zip_data_hash(ctx->appx_ctx->zip, EVP_sha256(), &cdOffset);
	ctx->appx_ctx->calculatedCDHash = appx_calc_zip_central_directory_hash(ctx->appx_ctx->zip, EVP_sha256(), cdOffset);
	ctx->appx_ctx->calculatedCIHash = zipCalcDigest(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME, true, EVP_sha256());

	if (!ctx->appx_ctx->calculatedBMHash || !ctx->appx_ctx->calculatedCTHash
		|| !ctx->appx_ctx->calculatedCDHash || !ctx->appx_ctx->calculatedDataHash)
	{
		printf("One or more hashes calculation failed\n");
		return 0;
	}

	if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->calculatedCIHash)
	{
		printf("Code integrity file exists, but CI hash calculation failed\n");
		return 0;
	}

	return 1;
}

//Check if the signature exists.
int appx_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
	if (detached)
	{
		printf("APPX does not support detached option\n");
		return 0;
	}

	appx_calculate_hashes(ctx);

	if (!zipEntryExist(ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME))
	{
		printf("%s does not exist\n", APP_SIGNATURE_FILENAME);
		return 0;
	}

	return 1;
}

bool appx_extract_hashes(FILE_FORMAT_CTX *ctx, SpcIndirectDataContent *content)
{
	content->data->value->value.sequence->data;

	//AppxSpcSipInfo *si = NULL;
	//uint8_t *blob = content->data->value->value.sequence->data;
	//d2i_AppxSpcSipInfo(&si, &blob, content->data->value->value.sequence->length);

	//long a = ASN1_INTEGER_get(si->a);
	//long b = ASN1_INTEGER_get(si->b);
	//long c = ASN1_INTEGER_get(si->c);
	//long d = ASN1_INTEGER_get(si->d);
	//long e = ASN1_INTEGER_get(si->e);
	//long f = ASN1_INTEGER_get(si->f);
	//BIO *stdbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	//printf("a: 0x%x b: 0x%x c: 0x%x d: 0x%x e: 0x%x f: 0x%x\n", a, b, c, d, e, f);
	//ASN1_STRING_print_ex(stdbio, si->string, ASN1_STRFLGS_RFC2253);

	//AppxSpcSipInfo_free(si);

	int length = content->messageDigest->digest->length;
	uint8_t *data = content->messageDigest->digest->data;

	//we are expecting at least 4 hashes + 4 byte header
	if (length < 4 * SHA256_DIGEST_LENGTH + 4)
	{
		printf("Hash too short\n");
		return false;
	}

	OPENSSL_free(ctx->appx_ctx->existingBMHash);
	OPENSSL_free(ctx->appx_ctx->existingCTHash);
	OPENSSL_free(ctx->appx_ctx->existingCDHash);
	OPENSSL_free(ctx->appx_ctx->existingDataHash);
	OPENSSL_free(ctx->appx_ctx->existingCIHash);

	ctx->appx_ctx->existingBMHash = NULL;
	ctx->appx_ctx->existingCIHash = NULL;
	ctx->appx_ctx->existingBMHash = NULL;
	ctx->appx_ctx->existingDataHash = NULL;
	ctx->appx_ctx->existingCIHash = NULL;

	if (memcmp(data, APPX_SIGNATURE, 4))
	{
		printf("Hash signature does not match\n");
		return false;
	}

	int pos = 4;

	while (pos + SHA256_DIGEST_LENGTH + 4 <= length)
	{
		if (!memcmp(data + pos, AXPC_SIGNATURE, 4))
		{
			ctx->appx_ctx->existingDataHash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
			memcpy(ctx->appx_ctx->existingDataHash, data + pos + 4, SHA256_DIGEST_LENGTH);
		}
		else if (!memcmp(data + pos, AXCD_SIGNATURE, 4))
		{
			ctx->appx_ctx->existingCDHash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
			memcpy(ctx->appx_ctx->existingCDHash, data + pos + 4, SHA256_DIGEST_LENGTH);
		}
		else if (!memcmp(data + pos, AXCT_SIGNATURE, 4))
		{
			ctx->appx_ctx->existingCTHash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
			memcpy(ctx->appx_ctx->existingCTHash, data + pos + 4, SHA256_DIGEST_LENGTH);
		}
		else if (!memcmp(data + pos, AXBM_SIGNATURE, 4))
		{
			ctx->appx_ctx->existingBMHash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
			memcpy(ctx->appx_ctx->existingBMHash, data + pos + 4, SHA256_DIGEST_LENGTH);
		}
		else if (!memcmp(data + pos, AXCI_SIGNATURE, 4))
		{
			ctx->appx_ctx->existingCIHash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
			memcpy(ctx->appx_ctx->existingCIHash, data + pos + 4, SHA256_DIGEST_LENGTH);
		}
		else
		{
			printf("Invalid hash signature\n");
		}

		pos += SHA256_DIGEST_LENGTH + 4;
	}

	if (!ctx->appx_ctx->existingDataHash)
	{
		printf("File hash missing\n");
		return false;
	}

	if (!ctx->appx_ctx->existingCDHash)
	{
		printf("Central directory hash missing\n");
		return false;
	}

	if (!ctx->appx_ctx->existingBMHash)
	{
		printf("Block map hash missing\n");
		return false;
	}

	if (!ctx->appx_ctx->existingCTHash)
	{
		printf("Content types hash missing\n");
		return false;
	}

	if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->existingCIHash)
	{
		printf("Code integrity hash missing\n");
		return false;
	}

	return true;
}

bool appx_compare_hashes(FILE_FORMAT_CTX *ctx)
{
	if (ctx->appx_ctx->calculatedBMHash && ctx->appx_ctx->existingBMHash)
	{
		printf("Checking Block Map hashes:\n");

		if (!compare_digests(ctx->appx_ctx->existingBMHash, ctx->appx_ctx->calculatedBMHash, NID_sha256))
		{
			return false;
		}
	}
	else
	{
		printf("Block map hash missing\n");
		return false;
	}

	if (ctx->appx_ctx->calculatedCTHash && ctx->appx_ctx->existingCTHash)
	{
		printf("Checking Content Types hashes:\n");

		if (!compare_digests(ctx->appx_ctx->existingCTHash, ctx->appx_ctx->calculatedCTHash, NID_sha256))
		{
			return false;
		}
	}
	else
	{
		printf("Content Types hash missing\n");
		return false;
	}

	if (ctx->appx_ctx->calculatedDataHash && ctx->appx_ctx->existingDataHash)
	{
		printf("Checking Data hashes:\n");

		if (!compare_digests(ctx->appx_ctx->existingDataHash, ctx->appx_ctx->calculatedDataHash, NID_sha256))
		{
			return false;
		}
	}
	else
	{
		printf("Central Directory hash missing\n");
		return false;
	}

	if (ctx->appx_ctx->calculatedCDHash && ctx->appx_ctx->existingCDHash)
	{
		printf("Checking Central Directory hashes:\n");

		if (!compare_digests(ctx->appx_ctx->existingCDHash, ctx->appx_ctx->calculatedCDHash, NID_sha256))
		{
			return false;
		}
	}
	else
	{
		printf("Central Directory hash missing\n");
		return false;
	}

	if (ctx->appx_ctx->calculatedCIHash && ctx->appx_ctx->existingCIHash)
	{
		printf("Checking Code Integrity hashes:\n");

		if (!compare_digests(ctx->appx_ctx->existingCIHash, ctx->appx_ctx->calculatedCIHash, NID_sha256))
		{
			return false;
		}
	}
	else if (!ctx->appx_ctx->calculatedCIHash && !ctx->appx_ctx->existingCIHash)
	{
		//this is fine, CI file is optional -> if it is missing we expect both hashes to be non existent
	}
	else
	{
		printf("Code Integrity hash missing\n");
		return false;
	}

	return true;
}

int appx_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
	if (is_content_type(p7, SPC_INDIRECT_DATA_OBJID))
	{
		ASN1_STRING *content_val = p7->d.sign->contents->d.other->value.sequence;
		const u_char *p = content_val->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, content_val->length);
		if (idc)
		{
			if (!appx_extract_hashes(ctx, idc))
			{
				printf("Failed to extract hashes from the signature\n");
				SpcIndirectDataContent_free(idc);
				return 0; /* FAILED */
			}

			if (!appx_calculate_hashes(ctx))
			{
				printf("Failed to claculate one ore more hash\n");
				SpcIndirectDataContent_free(idc);
				return 0; /* FAILED */
			}

			if (!appx_compare_hashes(ctx))
			{
				printf("Signature hash verification failed\n");
				SpcIndirectDataContent_free(idc);
				return 0; /* FAILED */
			}

			SpcIndirectDataContent_free(idc);
		}
	}

	return 1;
}

PKCS7 *appx_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
	uint8_t *data = NULL;
	uint64_t dataSize = 0;
	if (!zipReadFileDataByName(ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME, &data, &dataSize, true))
	{
		return NULL;
	}

	char signature[4];
	uint64_t pos = 0;

	if (memcmp(data, PKCX_SIGNATURE, 4))
	{
		printf("Invalid PKCX header\n");
		free(data);

		return false;
	}

	uint8_t *blob = data + 4;

	return d2i_PKCS7(NULL, (const unsigned char **)&blob, dataSize - 4);
}

bool appx_remove_ct_signature_entry(zipFile_t *zip, zipCentralDirectoryEntry_t *entry)
{
	uint8_t *data;
	uint64_t dataSize;

	if (!zipReadFileData(zip, entry, &data, &dataSize, true))
	{
		return false;
	}

	char *cpos = strstr((char *)data, SIGNATURE_CONTENT_TYPES_ENTRY);

	if (!cpos)
	{
		//do not treat as en error
		printf("Did not find existing signature entry in %s\n", entry->fileName);
		return true;
	}

	int ipos = cpos - (char *)data;
	int len = strlen(SIGNATURE_CONTENT_TYPES_ENTRY);

	memcpy(data + ipos, data + ipos + len, dataSize - ipos - len);

	dataSize -= len;

	bool ret = zipOverrideFileData(zip, entry, data, dataSize, true);

	free(data);

	return ret;
}

bool appx_append_ct_signature_entry(zipFile_t *zip, zipCentralDirectoryEntry_t *entry)
{
	uint8_t *data;
	uint64_t dataSize;

	if (!zipReadFileData(zip, entry, &data, &dataSize, true))
	{
		return false;
	}

	char *existingEntry = strstr((char *)data, SIGNATURE_CONTENT_TYPES_ENTRY);

	if (existingEntry)
	{
		//do not append it twice
		return true;
	}

	char *cpos = strstr((char *)data, SIGNATURE_CONTENT_TYPES_CLOSING_TAG);

	if (!cpos)
	{
		printf("%s parsing error\n", entry->fileName);
		return false;
	}

	int ipos = cpos - (char *)data;

	int len = strlen(SIGNATURE_CONTENT_TYPES_ENTRY);

	uint64_t newSize = dataSize + len;
	uint8_t *newData = malloc(newSize);

	memcpy(newData, data, ipos);
	memcpy(newData + ipos, SIGNATURE_CONTENT_TYPES_ENTRY, len);
	memcpy(newData + ipos + len, data + ipos, dataSize - ipos);

	bool ret = zipOverrideFileData(zip, entry, newData, newSize, true);

	free(data);
	free(newData);

	return ret;
}

int appx_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
	zipFile_t *zip = ctx->appx_ctx->zip;

	zipCentralDirectoryEntry_t *entry = zipGetCDEntryByName(zip, CONTENT_TYPES_FILENAME);

	if (!entry)
	{
		printf("Not a valid .appx file: content types file missing\n");
		return -1;
	}

	if (!appx_remove_ct_signature_entry(zip, entry))
	{
		return -1;
	}

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		if (strcmp(APP_SIGNATURE_FILENAME, entry->fileName))
		{
			uint64_t dummy;
			if (!zipRewriteData(zip, entry, outdata, &dummy))
			{
				return -1;
			}
		}
	}

	uint64_t size = 0;

	int64_t cdOffset = BIO_tell(outdata);

	appx_write_central_directory(zip, outdata, true, cdOffset);

	return 0;
}

/*
 * Allocate and return SpcSipInfo object.
 * [out] p: SpcSipInfo data
 * [out] plen: SpcSipInfo data length
 * [in] ctx: structure holds input and output data (unused)
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_SIPINFO_OBJID
 */
ASN1_OBJECT *appx_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
	ASN1_OBJECT *dtype;
	AppxSpcSipInfo *si = AppxSpcSipInfo_new();

	/* squash the unused parameter warning */
	(void)ctx;

	ASN1_INTEGER_set(si->a, 0x01010000);
	ASN1_INTEGER_set(si->b, 0);
	ASN1_INTEGER_set(si->c, 0);
	ASN1_INTEGER_set(si->d, 0);
	ASN1_INTEGER_set(si->e, 0);
	ASN1_INTEGER_set(si->f, 0);

	if (ctx->appx_ctx->isBundle)
	{
		printf("Signing as a bundle\n");
		ASN1_OCTET_STRING_set(si->string, APPXBUNDLE_UUID, sizeof(APPXBUNDLE_UUID));
	}
	else
	{
		printf("Signing as a package\n");
		ASN1_OCTET_STRING_set(si->string, APPX_UUID, sizeof(APPX_UUID));
	}

	*plen = i2d_AppxSpcSipInfo(si, NULL);
	*p = OPENSSL_malloc((size_t)*plen);
	i2d_AppxSpcSipInfo(si, p);
	*p -= *plen;
	dtype = OBJ_txt2obj(SPC_SIPINFO_OBJID, 1);
	AppxSpcSipInfo_free(si);
	return dtype; /* OK */
}

/*
 * Replace the data part with the MS Authenticode spcIndirectDataContent blob
 * [out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [in] blob: SpcIndirectDataContent data
 * [in] len: SpcIndirectDataContent data length
 * [returns] 0 on error or 1 on success
 */
static int appx_pkcs7_set_spc_indirect_data_content(PKCS7 *p7, uint8_t *hash, int hashLen, u_char *buf, int len)
{
	u_char mdbuf[EVP_MAX_MD_SIZE];
	int seqhdrlen;
	BIO *bio;
	PKCS7 *td7;

	memcpy(buf + len, hash, hashLen);
	seqhdrlen = asn1_simple_hdr_len(buf, len);

	if ((bio = PKCS7_dataInit(p7, NULL)) == NULL)
	{
		printf("PKCS7_dataInit failed\n");
		return 0; /* FAILED */
	}

	BIO_write(bio, buf + seqhdrlen, len - seqhdrlen + hashLen);
	(void)BIO_flush(bio);

	if (!PKCS7_dataFinal(p7, bio))
	{
		printf("PKCS7_dataFinal failed\n");
		return 0; /* FAILED */
	}

	BIO_free_all(bio);

	td7 = PKCS7_new();
	td7->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	td7->d.other = ASN1_TYPE_new();
	td7->d.other->type = V_ASN1_SEQUENCE;
	td7->d.other->value.sequence = ASN1_STRING_new();
	ASN1_STRING_set(td7->d.other->value.sequence, buf, len + hashLen);

	if (!PKCS7_set_content(p7, td7))
	{
		PKCS7_free(td7);
		printf("PKCS7_set_content failed\n");
		return 0; /* FAILED */
	}

	return 1; /* OK */
}

/*
 * [out] blob: SpcIndirectDataContent data
 * [out] len: SpcIndirectDataContent data length
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] 0 on error or 1 on success
 */
static int appx_spc_indirect_data_content_get(u_char **blob, int *len, FILE_FORMAT_CTX *ctx, int hashLen)
{
	u_char *p = NULL;
	int l = 0;
	void *hash;
	SpcIndirectDataContent *idc = SpcIndirectDataContent_new();

	idc->data->value = ASN1_TYPE_new();
	idc->data->value->type = V_ASN1_SEQUENCE;
	idc->data->value->value.sequence = ASN1_STRING_new();
	idc->data->type = ctx->format->data_blob_get(&p, &l, ctx);
	idc->data->value->value.sequence->data = p;
	idc->data->value->value.sequence->length = l;
	idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(NID_sha256);
	idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
	idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

	hash = OPENSSL_malloc((size_t)hashLen);
	memset(hash, 0, (size_t)hashLen);
	ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashLen);
	OPENSSL_free(hash);

	*len = i2d_SpcIndirectDataContent(idc, NULL);
	*blob = OPENSSL_malloc((size_t)*len);
	p = *blob;
	i2d_SpcIndirectDataContent(idc, &p);
	SpcIndirectDataContent_free(idc);
	*len -= hashLen;
	return 1; /* OK */
}

/*
 * [out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
int appx_pkcs7_set_data_content(PKCS7 *p7, uint8_t *hash, int hashLen, FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	int len = 0;
	u_char *buf;

	if (!appx_spc_indirect_data_content_get(&p, &len, ctx, hashLen))
		return 0; /* FAILED */
	buf = OPENSSL_malloc(SIZE_64K);
	memcpy(buf, p, (size_t)len);
	OPENSSL_free(p);
	if (!appx_pkcs7_set_spc_indirect_data_content(p7, hash, hashLen, buf, len)) {
		OPENSSL_free(buf);
		return 0; /* FAILED */
	}
	OPENSSL_free(buf);

	return 1; /* OK */
}

/*
 * [in, out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [returns] 0 on error or 1 on success
 */
int appx_add_indirect_data_object(PKCS7 *p7, uint8_t *hash, int hashLen, FILE_FORMAT_CTX *ctx)
{
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	PKCS7_SIGNER_INFO *si;

	signer_info = PKCS7_get_signer_info(p7);
	if (!signer_info)
		return 0; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 0; /* FAILED */
	if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
		V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1)))
		return 0; /* FAILED */
	if (!appx_pkcs7_set_data_content(p7, hash, hashLen, ctx)) {
		printf("Signing failed\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

uint8_t *appx_hash_blob_get(FILE_FORMAT_CTX *ctx, int *plen)
{
	int dataSize = ctx->appx_ctx->calculatedCIHash ? 4 + 5 * (SHA256_DIGEST_LENGTH + 4) : 4 + 4 * (SHA256_DIGEST_LENGTH + 4);
	uint8_t *data = OPENSSL_malloc(dataSize);

	int pos = 0;

	memcpy(data + pos, APPX_SIGNATURE, 4);
	pos += 4;

	memcpy(data + pos, AXPC_SIGNATURE, 4);
	pos += 4;
	memcpy(data + pos, ctx->appx_ctx->calculatedDataHash, SHA256_DIGEST_LENGTH);
	pos += SHA256_DIGEST_LENGTH;

	memcpy(data + pos, AXCD_SIGNATURE, 4);
	pos += 4;
	memcpy(data + pos, ctx->appx_ctx->calculatedCDHash, SHA256_DIGEST_LENGTH);
	pos += SHA256_DIGEST_LENGTH;

	memcpy(data + pos, AXCT_SIGNATURE, 4);
	pos += 4;
	memcpy(data + pos, ctx->appx_ctx->calculatedCTHash, SHA256_DIGEST_LENGTH);
	pos += SHA256_DIGEST_LENGTH;

	memcpy(data + pos, AXBM_SIGNATURE, 4);
	pos += 4;
	memcpy(data + pos, ctx->appx_ctx->calculatedBMHash, SHA256_DIGEST_LENGTH);
	pos += SHA256_DIGEST_LENGTH;

	if (ctx->appx_ctx->calculatedCIHash)
	{
		memcpy(data + pos, AXCI_SIGNATURE, 4);
		pos += 4;
		memcpy(data + pos, ctx->appx_ctx->calculatedCIHash, SHA256_DIGEST_LENGTH);
		pos += SHA256_DIGEST_LENGTH;
	}

	*plen = pos;
	return data;
}

/*
 * Obtain an existing signature or create a new one.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [out] outdata: outdata file BIO (unused)
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *appx_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
	PKCS7 *cursig = NULL, *p7 = NULL;

	/* squash unused parameter warnings */
	(void)outdata;
	(void)hash;

	if (ctx->options->cmd == CMD_ADD || ctx->options->cmd == CMD_ATTACH)
	{
		/* Obtain an existing signature */
		cursig = appx_pkcs7_extract(ctx);

		if (!cursig)
		{
			printf("Unable to extract existing signature\n");
			return NULL; /* FAILED */
		}

		return cursig;
	}
	else if (ctx->options->cmd == CMD_SIGN)
	{
		/* Create a new signature */
		zipCentralDirectoryEntry_t *entry = zipGetCDEntryByName(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME);

		if (!entry)
		{
			printf("Not a valid .appx file: content types file missing\n");
			return NULL;
		}

		if (!appx_append_ct_signature_entry(ctx->appx_ctx->zip, entry))
		{
			return NULL;
		}
		
		if (!appx_calculate_hashes(ctx))
		{
			printf("Failed to claculate one ore more hash\n");
			return NULL;
		}

		/* Create a new PKCS#7 signature */
		p7 = pkcs7_create(ctx);
		if (!p7)
		{
			printf("Creating a new signature failed\n");
			return NULL; /* FAILED */
		}

		int len = 0;
		uint8_t *hashBlob = appx_hash_blob_get(ctx, &len);

		if (!appx_add_indirect_data_object(p7, hashBlob, len, ctx)) {
			printf("Adding SPC_INDIRECT_DATA_OBJID failed\n");
			OPENSSL_free(hashBlob);
			PKCS7_free(p7);
			return NULL; /* FAILED */
		}

		OPENSSL_free(hashBlob);
	}

	return p7; /* OK */
}

int appx_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
	zipFile_t *zip = ctx->appx_ctx->zip;

	zipCentralDirectoryEntry_t *prev = NULL;
	zipCentralDirectoryEntry_t *last = NULL;

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; )
	{
		last = entry;

		if (strcmp(APP_SIGNATURE_FILENAME, entry->fileName))
		{
			uint64_t dummy = 0;
			if (!zipRewriteData(zip, entry, outdata, &dummy))
			{
				return -1;
			}

			prev = entry;
			entry = entry->next;
		}
		else
		{
			//remove the entry
			//actually this code is pretty naive - if you remove the entry that was not at the end
			//everything will go south - the offsets in the CD will not match the local header offsets.
			//that can be fixed here or left as is - signtool & this tool always appends the signatuee file at the end.
			//Might be a problem when someone decides to unpack & repack the .appx zip file
			zipCentralDirectoryEntry_t *current = entry;
			entry = entry->next;

			if (prev)
			{
				prev->next = entry;
			}

			freeZipCentralDirectoryEntry(current);
		}
	}

	if (!last)
	{
		//not really possible unless an empty zip file, but who knows
		return -1;
	}

	//create the signature entry
	uint8_t *der = NULL;
	int noBytes = i2d_PKCS7(p7, &der);

	if (noBytes <= 0)
	{
		return -1;
	}

	uint8_t *blob = malloc(noBytes + 4);
	memcpy(blob, PKCX_SIGNATURE, 4);
	memcpy(blob + 4, der, noBytes);

	noBytes += 4;

	if (!zipAppendFile(zip, outdata, APP_SIGNATURE_FILENAME, blob, noBytes, true))
	{
		free(blob);
		return -1;
	}


	OPENSSL_free(der);

	free(blob);

	int64_t cdOffset = BIO_tell(outdata); //again, 32bit api -> will limit us to 2GB files

	appx_write_central_directory(zip, outdata, false, cdOffset);

	return 0;
}

BIO *appx_bio_free(BIO *hash, BIO *outdata)
{
	BIO_free_all(outdata);
	BIO_free_all(hash);
	return NULL;
}

void appx_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
	freeZip(ctx->appx_ctx->zip);
	OPENSSL_free(ctx->appx_ctx->calculatedBMHash);
	OPENSSL_free(ctx->appx_ctx->calculatedCTHash);
	OPENSSL_free(ctx->appx_ctx->calculatedCDHash);
	OPENSSL_free(ctx->appx_ctx->calculatedDataHash);
	OPENSSL_free(ctx->appx_ctx->calculatedCIHash);
	OPENSSL_free(ctx->appx_ctx->existingBMHash);
	OPENSSL_free(ctx->appx_ctx->existingCTHash);
	OPENSSL_free(ctx->appx_ctx->existingCDHash);
	OPENSSL_free(ctx->appx_ctx->existingDataHash);
	OPENSSL_free(ctx->appx_ctx->existingCIHash);

	OPENSSL_free(ctx->appx_ctx);
	OPENSSL_free(ctx);
}
