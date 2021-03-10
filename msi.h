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

#define DIR_UNKNOWN      0
#define DIR_STORAGE      1
#define DIR_STREAM       2
#define DIR_ROOT         5

#define RED_COLOR        0
#define BLACK_COLOR      1

#define DIFAT_IN_HEADER  109

#define HEADER_SIGNATURE            0x00
#define HEADER_CLSID                0x08   /* reserved and unused */
#define HEADER_MINOR_VER            0x18   /* 0x33 and 0x3e have been seen */
#define HEADER_MAJOR_VER            0x1a   /* 0x3 been seen in wild */
#define HEADER_BYTE_ORDER           0x1c   /* 0xfe 0xff == Intel Little Endian */
#define HEADER_SECTOR_SHIFT         0x1e
#define HEADER_MINI_SECTOR_SHIFT    0x20
#define RESERVED                    0x22   /* reserved and unused */
#define HEADER_DIR_SECTOR           0x28
#define HEADER_FAT_SECTOR           0x2c
#define HEADER_DIR_SECTOR_LOC       0x30
#define HEADER_TRANSACTION          0x34
#define HEADER_STREAM_CUTOFF_SIZE   0x38
#define HEADER_MINI_FAT_SECTOR_LOC  0x3c
#define HEADER_MINI_FAT_SECTOR      0x40
#define HEADER_DIFAT_FAT_SECTOR_LOC 0x44
#define HEADER_DIFAT_FAT_SECTOR     0x48
#define HEADER_DIFAT                0x4c

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

#define GET_UINT16_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8))

#define GET_UINT32_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8) | \
			(((u_char*)(p))[2]<<16) | (((u_char*)(p))[3]<<24))

typedef struct {
	unsigned char signature[8];     /* 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 */
	unsigned char unused_clsid[16]; /* reserved and unused */
	uint16_t minorVersion;
	uint16_t majorVersion;
	uint16_t byteOrder;
	uint16_t sectorShift;           /* power of 2 */
	uint16_t miniSectorShift;       /* power of 2 */
	unsigned char reserved[6];      /* reserved and unused */
	uint32_t numDirectorySector;
	uint32_t numFATSector;
	uint32_t firstDirectorySectorLocation;
	uint32_t transactionSignatureNumber;
	uint32_t miniStreamCutoffSize;
	uint32_t firstMiniFATSectorLocation;
	uint32_t numMiniFATSector;
	uint32_t firstDIFATSectorLocation;
	uint32_t numDIFATSector;
	uint32_t headerDIFAT[DIFAT_IN_HEADER];
} MSI_FILE_HDR;

typedef struct {
	unsigned char name[DIRENT_MAX_NAME_SIZE];
	uint16_t nameLen;
	uint8_t type;
	uint8_t colorFlag;
	uint32_t leftSiblingID;     /* Note that it's actually the left/right child in the RB-tree */
	uint32_t rightSiblingID;    /* so entry.leftSibling.rightSibling does NOT go back to entry */
	uint32_t childID;
	unsigned char clsid[16];
	unsigned char stateBits[4];
	unsigned char creationTime[8];
	unsigned char modifiedTime[8];
	uint32_t startSectorLocation;
	unsigned char size[8];
} MSI_FILE_ENTRY;

typedef struct {
	unsigned char name[DIRENT_MAX_NAME_SIZE];
	uint16_t nameLen;
	uint8_t type;
	MSI_FILE_ENTRY *entry;
	STACK_OF(MSI_DIR_ENTRY) *children;
} MSI_DIR_ENTRY;

DEFINE_STACK_OF(MSI_DIR_ENTRY)

typedef struct {
	const unsigned char *m_buffer;
	size_t m_bufferLen;
	MSI_FILE_HDR *m_hdr;
	size_t m_sectorSize;
	size_t m_minisectorSize;
	size_t m_miniStreamStartSector;
} MSI_FILE;

static u_char msi_magic[] = {
	0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
};

static const u_char digital_signature[] = {
	0x05, 0x00, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00,
	0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00,
	0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00,
	0x65, 0x00
};

static const u_char digital_signature_ex[] = {
	0x05, 0x00, 0x4D, 0x00, 0x73, 0x00, 0x69, 0x00,
	0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00,
	0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53, 0x00,
	0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00,
	0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00,
	0x45, 0x00, 0x78, 0x00
};

int msi_read_file(MSI_FILE *msi, MSI_FILE_ENTRY *entry, size_t offset, char *buffer, size_t len);
MSI_FILE *msi_msifile_new(char *buffer, size_t len);
void msi_msifile_free(MSI_FILE *msi);
MSI_FILE_ENTRY *msi_get_root_entry(MSI_FILE *msi);
MSI_DIR_ENTRY *msi_dirent_new(MSI_FILE *msi, MSI_FILE_ENTRY *entry,
		MSI_DIR_ENTRY *parent, MSI_FILE_ENTRY **ds, MSI_FILE_ENTRY **dse);
int msi_dirent_free(MSI_DIR_ENTRY *dirent);
MSI_FILE_HDR *msi_get_file_info(MSI_FILE *msi);
int msi_prehash_dir(MSI_DIR_ENTRY *dirent, BIO *hash);
int msi_hash_dir(MSI_FILE *msi, MSI_DIR_ENTRY *dirent, BIO *hash);
void msi_calc_digest(char *indata, const EVP_MD *md, unsigned char *mdbuf, size_t fileend);
