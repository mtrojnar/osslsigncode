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

#include <stdint.h>
#include <openssl/safestack.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define MAXREGSECT       0xfffffffa   /* maximum regular sector number */
#define DIFSECT          0xfffffffc   /* specifies a DIFAT sector in the FAT */
#define FATSECT          0xfffffffd   /* specifies a FAT sector in the FAT */
#define ENDOFCHAIN       0xfffffffe   /* end of a linked chain of sectors */
#define NOSTREAM         0xffffffff   /* terminator or empty pointer */
#define FREESECT         0xffffffff   /* empty unallocated free sectors */

#define DIR_UNKNOWN      0
#define DIR_STORAGE      1
#define DIR_STREAM       2
#define DIR_ROOT         5

#define RED_COLOR        0
#define BLACK_COLOR      1

#define DIFAT_IN_HEADER             109
#define MINI_STREAM_CUTOFF_SIZE     0x00001000 /* 4096 bytes */
#define HEADER_SIZE                 0x200  /* 512 bytes, independent of sector size */
#define MAX_SECTOR_SIZE             0x1000 /* 4096 bytes */

#define HEADER_SIGNATURE            0x00   /* 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 */
#define HEADER_CLSID                0x08   /* reserved and unused */
#define HEADER_MINOR_VER            0x18   /* SHOULD be set to 0x003E */
#define HEADER_MAJOR_VER            0x1a   /* MUST be set to either 0x0003 (version 3) or 0x0004 (version 4) */
#define HEADER_BYTE_ORDER           0x1c   /* 0xfe 0xff == Intel Little Endian */
#define HEADER_SECTOR_SHIFT         0x1e   /* MUST be set to 0x0009, or 0x000c */
#define HEADER_MINI_SECTOR_SHIFT    0x20   /* MUST be set to 0x0006 */
#define RESERVED                    0x22   /* reserved and unused */
#define HEADER_DIR_SECTORS_NUM      0x28
#define HEADER_FAT_SECTORS_NUM      0x2c
#define HEADER_DIR_SECTOR_LOC       0x30
#define HEADER_TRANSACTION          0x34
#define HEADER_MINI_STREAM_CUTOFF   0x38   /* 4096 bytes */
#define HEADER_MINI_FAT_SECTOR_LOC  0x3c
#define HEADER_MINI_FAT_SECTORS_NUM 0x40
#define HEADER_DIFAT_SECTOR_LOC     0x44
#define HEADER_DIFAT_SECTORS_NUM    0x48
#define HEADER_DIFAT                0x4c

#define DIRENT_SIZE                 0x80   /* 128 bytes */
#define DIRENT_MAX_NAME_SIZE        0x40   /* 64 bytes */

#define DIRENT_NAME                 0x00
#define DIRENT_NAME_LEN             0x40   /* length in bytes incl 0 terminator */
#define DIRENT_TYPE                 0x42
#define DIRENT_COLOUR               0x43
#define DIRENT_LEFT_SIBLING_ID      0x44
#define DIRENT_RIGHT_SIBLING_ID     0x48
#define DIRENT_CHILD_ID             0x4c
#define DIRENT_CLSID                0x50
#define DIRENT_STATE_BITS           0x60
#define DIRENT_CREATE_TIME          0x64
#define DIRENT_MODIFY_TIME          0x6c
#define DIRENT_START_SECTOR_LOC     0x74
#define DIRENT_FILE_SIZE            0x78

#define GET_UINT8_LE(p) ((u_char*)(p))[0]

#define GET_UINT16_LE(p) (uint16_t)(((u_char*)(p))[0] | (((u_char*)(p))[1]<<8))

#define GET_UINT32_LE(p) (uint32_t)(((u_char*)(p))[0] | (((u_char*)(p))[1]<<8) | \
			(((u_char*)(p))[2]<<16) | (((u_char*)(p))[3]<<24))

#define PUT_UINT8_LE(i,p) \
	((u_char*)(p))[0] = (i) & 0xff;
	
#define PUT_UINT16_LE(i,p) \
	((u_char*)(p))[0] = (i) & 0xff; \
	((u_char*)(p))[1] = ((i)>>8) & 0xff

#define PUT_UINT32_LE(i,p) \
	((u_char*)(p))[0] = (i) & 0xff; \
	((u_char*)(p))[1] = ((i)>>8) & 0xff; \
	((u_char*)(p))[2] = ((i)>>16) & 0xff; \
	((u_char*)(p))[3] = ((i)>>24) & 0xff

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

typedef unsigned char u_char;

typedef struct {
	u_char signature[8];      /* 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 */
	u_char unused_clsid[16];  /* reserved and unused */
	uint16_t minorVersion;
	uint16_t majorVersion;
	uint16_t byteOrder;
	uint16_t sectorShift;     /* power of 2 */
	uint16_t miniSectorShift; /* power of 2 */
	u_char reserved[6];       /* reserved and unused */
	uint32_t numDirectorySector;
	uint32_t numFATSector;
	uint32_t firstDirectorySectorLocation;
	uint32_t transactionSignatureNumber; /* reserved */
	uint32_t miniStreamCutoffSize;
	uint32_t firstMiniFATSectorLocation;
	uint32_t numMiniFATSector;
	uint32_t firstDIFATSectorLocation;
	uint32_t numDIFATSector;
	uint32_t headerDIFAT[DIFAT_IN_HEADER];
} MSI_FILE_HDR;

typedef struct {
	u_char name[DIRENT_MAX_NAME_SIZE];
	uint16_t nameLen;
	uint8_t type;
	uint8_t colorFlag;
	uint32_t leftSiblingID;
	uint32_t rightSiblingID;
	uint32_t childID;
	u_char clsid[16];
	u_char stateBits[4];
	u_char creationTime[8];
	u_char modifiedTime[8];
	uint32_t startSectorLocation;
	u_char size[8];
} MSI_ENTRY;

typedef struct {
	u_char name[DIRENT_MAX_NAME_SIZE];
	uint16_t nameLen;
	uint8_t type;
	MSI_ENTRY *entry;
	STACK_OF(MSI_DIRENT) *children;
} MSI_DIRENT;

DEFINE_STACK_OF(MSI_DIRENT)

typedef struct {
	const u_char *m_buffer;
	uint32_t m_bufferLen;
	MSI_FILE_HDR *m_hdr;
	uint32_t m_sectorSize;
	uint32_t m_minisectorSize;
	uint32_t m_miniStreamStartSector;
} MSI_FILE;

typedef struct {
	char *header;
	char *ministream;
	char *minifat;
	char *fat;
	uint32_t dirtreeLen;
	uint32_t miniStreamLen;
	uint32_t minifatLen;
	uint32_t fatLen;
	int ministreamsMemallocCount;
	int minifatMemallocCount;
	int fatMemallocCount;
	int dirtreeSectorsCount;
	int minifatSectorsCount;
	int fatSectorsCount;
	int miniSectorNum;
	int sectorNum;
	uint32_t sectorSize;
} MSI_OUT;

static u_char msi_magic[] = {
	0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
};

static const u_char digital_signature[] = {
	0x05, 0x00, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00,
	0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00,
	0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00,
	0x65, 0x00, 0x00, 0x00
};

static const u_char digital_signature_ex[] = {
	0x05, 0x00, 0x4D, 0x00, 0x73, 0x00, 0x69, 0x00,
	0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00,
	0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53, 0x00,
	0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00,
	0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00,
	0x45, 0x00, 0x78, 0x00, 0x00, 0x00
};

int msi_file_read(MSI_FILE *msi, MSI_ENTRY *entry, uint32_t offset, char *buffer, uint32_t len);
MSI_FILE *msi_file_new(char *buffer, uint32_t len);
void msi_file_free(MSI_FILE *msi);
MSI_ENTRY *msi_root_entry_get(MSI_FILE *msi);
int msi_dirent_new(MSI_FILE *msi, MSI_ENTRY *entry, MSI_DIRENT *parent, MSI_DIRENT **ret);
MSI_ENTRY *msi_signatures_get(MSI_DIRENT *dirent, MSI_ENTRY **dse);
void msi_dirent_free(MSI_DIRENT *dirent);
MSI_FILE_HDR *msi_header_get(MSI_FILE *msi);
int msi_prehash_dir(MSI_DIRENT *dirent, BIO *hash, int is_root);
int msi_hash_dir(MSI_FILE *msi, MSI_DIRENT *dirent, BIO *hash, int is_root);
int msi_calc_digest(char *indata, const EVP_MD *md, u_char *mdbuf, uint32_t fileend);
int msi_dirent_delete(MSI_DIRENT *dirent, const u_char *name, uint16_t nameLen);
int msi_file_write(MSI_FILE *msi, MSI_DIRENT *dirent, u_char *p, int len, u_char *p_msiex, int len_msiex, BIO *outdata);
