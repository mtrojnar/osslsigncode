/*
 * APPX file support library
 *
 * Copyright (C) 2023 Maciej Panek <maciej.panek_malpa_punxworks.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

#define _FILE_OFFSET_BITS 64

#include "osslsigncode.h"
#include "helpers.h"

#include <zlib.h>

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
static const char *CODE_INTEGRITY_FILENAME = "AppxMetadata/CodeIntegrity.cat";

static const char PKCX_SIGNATURE[4] = { 'P', 'K', 'C', 'X' }; //Main header header
static const char APPX_SIGNATURE[4] = { 'A', 'P', 'P', 'X' }; //APPX header
static const char AXPC_SIGNATURE[4] = { 'A', 'X', 'P', 'C' }; //digest of zip file records
static const char AXCD_SIGNATURE[4] = { 'A', 'X', 'C', 'D' }; //digest zip file central directory
static const char AXCT_SIGNATURE[4] = { 'A', 'X', 'C', 'T' }; //digest of uncompressed [ContentTypes].xml
static const char AXBM_SIGNATURE[4] = { 'A', 'X', 'B', 'M' }; //digest of uncompressed AppxBlockMap.xml
static const char AXCI_SIGNATURE[4] = { 'A', 'X', 'C', 'I' }; //digest of uncompressed AppxMetadata/CodeIntegrity.cat (optional)

#define EOCDR_SIZE 22
#define ZIP64_EOCD_LOCATOR_SIZE 20
#define ZIP64_HEADER 0x100
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
} zipLocalHeader_t;

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

void bufferAddU8(uint8_t *buffer, uint64_t *pos, uint8_t v)
{
	buffer[*pos] = v;
	*pos += 1;
}

void bufferAddU16(uint8_t *buffer, uint64_t *pos, uint16_t v)
{
	buffer[*pos] = v & 0xFF;
	buffer[*pos + 1] = (v >> 8) & 0xFF;
	*pos += 2;
}

void bufferAddU32(uint8_t *buffer, uint64_t *pos, uint32_t v)
{
	buffer[*pos] = v & 0xFF;
	buffer[*pos + 1] = (v >> 8) & 0xFF;
	buffer[*pos + 2] = (v >> 16) & 0xFF;
	buffer[*pos + 3] = (v >> 24) & 0xFF;

	*pos += 4;
}

void bufferAddU64(uint8_t *buffer, uint64_t *pos, uint64_t v)
{
	uint32_t l = v & 0xFFFFFFFF;
	uint32_t h = (v >> 32) & 0xFFFFFFFF;

	bufferAddU32(buffer, pos, l);
	bufferAddU32(buffer, pos, h);
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

	if (eocdr->centralDirectoryDiskNumber > 1 || eocdr->diskNumber > 1 ||
		eocdr->centralDirectoryDiskNumber != eocdr->diskNumber ||
		eocdr->diskEntries != eocdr->totalEntries)
	{
		printf("The input file is a multipart archive - not supported\n");
		return false;
	}

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

uint64_t zipGetLocalHeaderSize(zipFile_t *zip, bool includeDataDescriptor)
{
	char signature[4];

	fread(signature, 1, 4, zip->f);

	if (memcmp(signature, PKZIP_LH_SIGNATURE, 4))
	{
		printf("The input file is not a valip zip file - local header signature does not match\n");
		return 0;
	}

	uint64_t ret = 30;

	fseeko(zip->f, 2, SEEK_CUR);
	uint16_t flags = fileGetU16(zip->f);
	fseeko(zip->f, 18, SEEK_CUR);
	ret += fileGetU16(zip->f);
	ret += fileGetU16(zip->f);

	if (includeDataDescriptor && (flags & DATA_DESCRIPTOR_BIT))
	{
		if (zip->isZip64)
		{
			ret += 24;
		}
		else
		{
			ret += 16;
		}
	}

	return ret;
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

			if (header->compressedSize == 0xFFFFFFFF)
			{
				if (len >= 8)
				{
					header->compressedSize = bufferGetU64(header->extraField, &pos);
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

			if (header->uncompressedSize == 0xFFFFFFFF)
			{
				if (len >= 16)
				{
					header->uncompressedSize = bufferGetU64(header->extraField, &pos);
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
			freeZipCentralDirectoryEntry(header);
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

	if (entry->extraField > 0)
	{
		entry->extraField = calloc(1, entry->extraFieldLen);
		fread(entry->extraField, 1, entry->extraFieldLen, f);
	}

	if (entry->fileCommentLen > 0)
	{
		entry->fileComment = calloc(1, entry->fileComment + 1);
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

			if (entry->compressedSize == 0xFFFFFFFF)
			{
				if (len >= 8)
				{
					entry->compressedSize = bufferGetU64(entry->extraField, &pos);
				}
				else
				{
					printf("Invalid zip64 central directory entry\n");
					freeZipCentralDirectoryEntry(entry);
					return NULL;
				}
			}

			if (entry->uncompressedSize == 0xFFFFFFFF)
			{
				if (len >= 16)
				{
					entry->uncompressedSize = bufferGetU64(entry->extraField, &pos);
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
	printf("Central directory entry count: %lld\n", zip->centralDirectoryRecordCount);

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		printf("Name: %s Compressed: %lld Uncompressed: %lld Offset: %lld\n", entry->fileName,
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

bool zipReadFileData(zipFile_t *zip, zipCentralDirectoryEntry_t *entry, uint8_t **pData, uint64_t *dataSize, bool unpack)
{
	FILE *f = zip->f;
	fseeko(f, entry->offsetOfLocalHeader, SEEK_SET);

	zipLocalHeader_t header;

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

	uint8_t *compressedData = malloc(entry->compressedSize);

	fread(compressedData, 1, entry->compressedSize, f);

	if (!unpack || unpack && entry->compression == COMPRESSION_NONE)
	{
		*pData = compressedData;
		*dataSize = entry->compressedSize;
	}
	else if (entry->compression == COMPRESSION_DEFLATE)
	{
		uint8_t *uncompressedData = malloc(entry->uncompressedSize);
		uLongf destLen = entry->uncompressedSize;
		uLongf sourceLen = entry->compressedSize;

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
			*dataSize = entry->uncompressedSize;
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
} appx_ctx_t;

/* FILE_FORMAT method prototypes */
/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *appx_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static ASN1_OBJECT *appx_data_blob_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static int appx_check_file(FILE_FORMAT_CTX *ctx, int detached);
static int appx_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *appx_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static int appx_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *appx_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int appx_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *appx_bio_free(BIO *hash, BIO *outdata);
static void appx_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_appx = {
    .ctx_new = appx_ctx_new, //ok
    .data_blob_get = appx_data_blob_get, //?
    .check_file = appx_check_file,
    .verify_digests = appx_verify_digests,
    .pkcs7_extract = appx_pkcs7_extract,
    .remove_pkcs7 = appx_remove_pkcs7,
    .pkcs7_prepare = appx_pkcs7_prepare, //?
    .append_pkcs7 = appx_append_pkcs7,
    .bio_free = appx_bio_free, //ok?
    .ctx_cleanup = appx_ctx_cleanup //ok?
};

FILE_FORMAT_CTX *appx_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
	zipFile_t *zip = openZip(options->infile);

	if (!zip)
	{
		return NULL;
	}

	zipPrintCentralDirectory(zip);

	FILE_FORMAT_CTX *ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
	ctx->appx_ctx = OPENSSL_zalloc(sizeof(appx_ctx_t));

	ctx->appx_ctx->zip = zip;
	ctx->format = &file_format_appx;
	ctx->options = options;

	return ctx;
}

ASN1_OBJECT *appx_data_blob_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
	return NULL;
}

uint8_t *appx_calc_zip_data_hash(zipFile_t *zip, const EVP_MD *md)
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

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		//the signature file is considered not existent for hashing purposes
		if (!strcmp(entry->fileName, APP_SIGNATURE_FILENAME))
		{
			continue;
		}

		fseeko(zip->f, entry->offsetOfLocalHeader, SEEK_SET);
		int64_t dataSize = zipGetLocalHeaderSize(zip, true);

		if (dataSize == 0)
		{
			BIO_free_all(bhash);
			return NULL;
		}

		dataSize += entry->compressedSize;

		fseeko(zip->f, entry->offsetOfLocalHeader, SEEK_SET);

		//printf("Will hash %lld bytes from file offset: %lld\n", dataSize, entry->offsetOfLocalHeader);

		uint8_t *data = malloc(SIZE_64K);

		while (dataSize > 0)
		{
			int64_t toRead = dataSize > SIZE_64K ? SIZE_64K : dataSize;
			dataSize -= toRead;
			fread(data, 1, toRead, zip->f);

			if (!bio_hash_data(bhash, data, 0, toRead))
			{
				free(data);
				BIO_free_all(bhash);
				return NULL;
			}
		}

		free(data);
	}

	mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);

	return mdbuf;
}

uint8_t *appx_eocdr_to_buffer(zipFile_t *zip, bool removeSignatureFile, uint64_t *size)
{
	uint64_t cdSize = 0;
	uint64_t cdShift = 0;

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		//the signature file is considered non existent for hashing purposes
		if (removeSignatureFile && !strcmp(entry->fileName, APP_SIGNATURE_FILENAME))
		{
			fseeko(zip->f, entry->offsetOfLocalHeader, SEEK_SET);
			int64_t dataSize = zipGetLocalHeaderSize(zip, true);

			if (dataSize == 0)
			{
				printf("Local header size calculation failed\n");
				return NULL;
			}

			dataSize += entry->compressedSize;

			//the central directory location would be in a different location is the signature file was not appended
			cdShift = dataSize;
			continue;
		}

		cdSize += entry->entryLen;
	}

	uint64_t pos = 0;

	//size of zip64 eocdr + zip64 eocd locator + zip eocdr
	uint64_t maxSize = cdSize + zip->eocdr.commentLen + zip->eocdr64.commentLen + 56 + 20 + 22;

	uint8_t *buffer = malloc(maxSize);

	if (zip->isZip64)
	{
		//eocdr
		memcpy(buffer, PKZIP64_EOCDR_SIGNATURE, 4);
		pos += 4;
		bufferAddU64(buffer, &pos, zip->eocdr64.eocdrSize);
		bufferAddU16(buffer, &pos, zip->eocdr64.creatorVersion);
		bufferAddU16(buffer, &pos, zip->eocdr64.viewerVersion);
		bufferAddU32(buffer, &pos, zip->eocdr64.diskNumber);
		bufferAddU32(buffer, &pos, zip->eocdr64.diskWithCentralDirectory);
		bufferAddU64(buffer, &pos, zip->eocdr64.diskEntries - (removeSignatureFile ? 1 : 0));
		bufferAddU64(buffer, &pos, zip->eocdr64.totalEntries - (removeSignatureFile ? 1 : 0));
		bufferAddU64(buffer, &pos, cdSize);
		bufferAddU64(buffer, &pos, zip->eocdr64.centralDirectoryOffset - cdShift);
		if (zip->eocdr64.commentLen > 0)
		{
			memcpy(buffer + pos, zip->eocdr64.comment, zip->eocdr64.commentLen);
			pos += zip->eocdr64.commentLen;
		}

		//eocdr locator
		memcpy(buffer + pos, PKZIP64_EOCD_LOCATOR_SIGNATURE, 4);
		pos += 4;
		bufferAddU32(buffer, &pos, zip->locator.diskWithEOCD);
		uint64_t newPos = zip->locator.eocdOffset - cdShift - (zip->eocdr64.centralDirectorySize - cdSize);
		bufferAddU64(buffer, &pos, newPos);
		bufferAddU32(buffer, &pos, zip->locator.totalNumberOfDisks);
	}

	memcpy(buffer + pos, PKZIP_EOCDR_SIGNATURE, 4);
	pos += 4;
	bufferAddU16(buffer, &pos, zip->eocdr.diskNumber);
	bufferAddU16(buffer, &pos, zip->eocdr.centralDirectoryDiskNumber);

	if (zip->eocdr.diskEntries != 0xFFFF)
	{
		bufferAddU16(buffer, &pos, zip->eocdr.diskEntries - (removeSignatureFile ? 1 : 0));
	}
	else
	{
		bufferAddU16(buffer, &pos, 0xFFFF);
	}

	if (zip->eocdr.totalEntries != 0xFFFF)
	{
		bufferAddU16(buffer, &pos, zip->eocdr.totalEntries - (removeSignatureFile ? 1 : 0));
	}
	else
	{
		bufferAddU16(buffer, &pos, 0xFFFF);
	}
	
	if (zip->eocdr.centralDirectorySize != 0xFFFFFFFF)
	{
		bufferAddU32(buffer, &pos, cdSize);
	}
	else
	{
		bufferAddU32(buffer, &pos, 0xFFFFFFFF);
	}

	if (zip->eocdr.centralDirectoryOffset != 0xFFFFFFFF)
	{
		bufferAddU32(buffer, &pos, zip->eocdr.centralDirectoryOffset - cdShift);
	}
	else
	{
		bufferAddU32(buffer, &pos, 0xFFFFFFFF);
	}

	bufferAddU16(buffer, &pos, zip->eocdr.commentLen);
	
	if (zip->eocdr.commentLen > 0)
	{
		memcpy(buffer + pos, zip->eocdr.comment, zip->eocdr.commentLen);
		pos += zip->eocdr.commentLen;
	}

	*size = pos;
	return buffer;
}

uint8_t *appx_calc_zip_central_directory_hash(zipFile_t *zip, const EVP_MD *md)
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

	for (zipCentralDirectoryEntry_t *entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next)
	{
		//the signature file is considered non existent for hashing purposes
		if (!strcmp(entry->fileName, APP_SIGNATURE_FILENAME))
		{
			continue;
		}

		uint64_t dataSize = entry->entryLen;
		uint8_t *data = malloc(dataSize);

		fseeko(zip->f, entry->fileOffset, SEEK_SET);
		fread(data, 1, dataSize, zip->f);

		if (!bio_hash_data(bhash, data, 0, dataSize))
		{
			free(data);
			BIO_free_all(bhash);
			return NULL;
		}

		free(data);
	}

	uint64_t dataSize = 0;
	uint8_t *data = appx_eocdr_to_buffer(zip, true, &dataSize);

	if (!data || !bio_hash_data(bhash, data, 0, dataSize))
	{
		free(data);
		BIO_free_all(bhash);
		return NULL;
	}

	free(data);

	mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);

	return mdbuf;
}

//Check if the signature exists.
int appx_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
	if (detached)
	{
		printf("APPX does not support detached option\n");
		return 0;
	}

	if (!zipEntryExist(ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME))
	{
		return 0;
	}

	return 1;
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
	ctx->appx_ctx->calculatedCDHash = appx_calc_zip_central_directory_hash(ctx->appx_ctx->zip, EVP_sha256());
	ctx->appx_ctx->calculatedDataHash = appx_calc_zip_data_hash(ctx->appx_ctx->zip, EVP_sha256());
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

bool appx_extract_hashes(FILE_FORMAT_CTX *ctx, SpcIndirectDataContent *content)
{
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

	if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->calculatedCIHash)
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

	if (ctx->appx_ctx->calculatedCIHash && ctx->appx_ctx->existingCIHash)
	{
		printf("Checking Code Integrity hashes:\n");

		if (!compare_digests(ctx->appx_ctx->existingDataHash, ctx->appx_ctx->calculatedDataHash, NID_sha256))
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
				printf("Signatue hash verification failed\n");
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

	return d2i_PKCS7(NULL, &blob, dataSize - 4);
}

int appx_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
	return 1;
}

#if 0
int appx_add_indirect_data_object(PKCS7 *p7, FILE_FORMAT_CTX *ctx)
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
	if (!pkcs7_set_data_content(p7, hash, ctx)) {
		printf("Signing failed\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}
#endif

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
#if 0
	/* squash unused parameter warnings */
	(void)outdata;
	(void)hash;

	/* Obtain an existing signature */
	cursig = appx_pkcs7_extract(ctx);
	if (!cursig)
	{
		printf("Unable to extract existing signature\n");
		return NULL; /* FAILED */
	}
	if (ctx->options->cmd == CMD_ADD || ctx->options->cmd == CMD_ATTACH) {
		p7 = cursig;
	}
	else if (ctx->options->cmd == CMD_SIGN)
	{
		/* Create a new signature */
		/* Create a new PKCS#7 signature */
		p7 = pkcs7_create(ctx);
		if (!p7) {
			printf("Creating a new signature failed\n");
			return NULL; /* FAILED */
		}
		if (!add_indirect_data_object(p7, hash, ctx)) {
			printf("Adding SPC_INDIRECT_DATA_OBJID failed\n");
			PKCS7_free(p7);
			return NULL; /* FAILED */
		}
	}
#endif
	return p7; /* OK */
}

int appx_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
	return 1;
}

BIO *appx_bio_free(BIO *hash, BIO *outdata)
{
	/* squash the unused parameter warning */
	(void)outdata;

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
