/*
 * MSI file support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * Reference specifications:
 * http://en.wikipedia.org/wiki/Compound_File_Binary_Format
 * https://msdn.microsoft.com/en-us/library/dd942138.aspx
 * https://github.com/microsoft/compoundfilereader
 */

#include "osslsigncode.h"
#include "helpers.h"

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

static const u_char msi_magic[] = {
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

static const u_char msi_root_entry[] = {
    0x52, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00,
    0x20, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x74, 0x00,
    0x72, 0x00, 0x79, 0x00, 0x00, 0x00
};

static const u_char msi_zeroes[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef struct {
    ASN1_INTEGER *a;
    ASN1_OCTET_STRING *string;
    ASN1_INTEGER *b;
    ASN1_INTEGER *c;
    ASN1_INTEGER *d;
    ASN1_INTEGER *e;
    ASN1_INTEGER *f;
} SpcSipInfo;

DECLARE_ASN1_FUNCTIONS(SpcSipInfo)

ASN1_SEQUENCE(SpcSipInfo) = {
    ASN1_SIMPLE(SpcSipInfo, a, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, string, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SpcSipInfo, b, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, c, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, d, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, e, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, f, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SpcSipInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSipInfo)

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

typedef struct msi_dirent_struct {
    u_char name[DIRENT_MAX_NAME_SIZE];
    uint16_t nameLen;
    uint8_t type;
    MSI_ENTRY *entry;
    STACK_OF(MSI_DIRENT) *children;
    struct msi_dirent_struct *next; /* for cycle detection */
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
    uint32_t ministreamsMemallocCount;
    uint32_t minifatMemallocCount;
    uint32_t fatMemallocCount;
    uint32_t dirtreeSectorsCount;
    uint32_t minifatSectorsCount;
    uint32_t fatSectorsCount;
    uint32_t miniSectorNum;
    uint32_t sectorNum;
    uint32_t sectorSize;
} MSI_OUT;

struct msi_ctx_st {
    MSI_FILE *msi;
    MSI_DIRENT *dirent;
    u_char *p_msiex; /* MsiDigitalSignatureEx stream data */
    uint32_t len_msiex; /* MsiDigitalSignatureEx stream data length */
    uint32_t fileend;
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *msi_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static ASN1_OBJECT *msi_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static int msi_check_file(FILE_FORMAT_CTX *ctx, int detached);
static u_char *msi_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md);
static int msi_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *msi_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static int msi_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *msi_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int msi_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *msi_bio_free(BIO *hash, BIO *outdata);
static void msi_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_msi = {
    .ctx_new = msi_ctx_new,
    .data_blob_get = msi_spc_sip_info_get,
    .check_file = msi_check_file,
    .digest_calc = msi_digest_calc,
    .verify_digests = msi_verify_digests,
    .pkcs7_extract = msi_pkcs7_extract,
    .remove_pkcs7 = msi_remove_pkcs7,
    .pkcs7_prepare = msi_pkcs7_prepare,
    .append_pkcs7 = msi_append_pkcs7,
    .bio_free = msi_bio_free,
    .ctx_cleanup = msi_ctx_cleanup
};

/* Prototypes */
static MSI_CTX *msi_ctx_get(char *indata, uint32_t filesize);
static PKCS7 *msi_pkcs7_get_digital_signature(FILE_FORMAT_CTX *ctx, MSI_ENTRY *ds,
    char **p, uint32_t len);
static int recurse_entry(MSI_FILE *msi, uint32_t entryID, MSI_DIRENT *parent);
static int msi_file_write(MSI_FILE *msi, MSI_DIRENT *dirent, u_char *p_msi, uint32_t len_msi,
        u_char *p_msiex, uint32_t len_msiex, BIO *outdata);
static MSI_ENTRY *msi_signatures_get(MSI_DIRENT *dirent, MSI_ENTRY **dse);
static int msi_file_read(MSI_FILE *msi, MSI_ENTRY *entry, uint32_t offset, char *buffer, uint32_t len);
static int msi_dirent_delete(MSI_DIRENT *dirent, const u_char *name, uint16_t nameLen);
static int msi_calc_MsiDigitalSignatureEx(FILE_FORMAT_CTX *ctx, BIO *hash);
static int msi_check_MsiDigitalSignatureEx(FILE_FORMAT_CTX *ctx, MSI_ENTRY *dse);
static int msi_hash_dir(MSI_FILE *msi, MSI_DIRENT *dirent, BIO *hash, int is_root);
static MSI_ENTRY *msi_root_entry_get(MSI_FILE *msi);
static void msi_file_free(MSI_FILE *msi);
static MSI_FILE *msi_file_new(char *buffer, uint32_t len);
static int msi_dirent_new(MSI_FILE *msi, MSI_ENTRY *entry, MSI_DIRENT *parent, MSI_DIRENT **ret);
static void msi_dirent_free(MSI_DIRENT *dirent);
static int msi_prehash_dir(MSI_DIRENT *dirent, BIO *hash, int is_root);

/*
 * FILE_FORMAT method definitions
 */

/*
 * Allocate and return a MSI file format context.
 * [in, out] options: structure holds the input data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO (unused)
 * [returns] pointer to MSI file format context
 */
static FILE_FORMAT_CTX *msi_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
    FILE_FORMAT_CTX *ctx;
    MSI_CTX *msi_ctx;
    uint32_t filesize;

    /* squash the unused parameter warning */
    (void)outdata;

    filesize = get_file_size(options->infile);
    if (filesize == 0)
        return NULL; /* FAILED */

    options->indata = map_file(options->infile, filesize);
    if (!options->indata) {
        return NULL; /* FAILED */
    }
    if (memcmp(options->indata, msi_magic, sizeof msi_magic)) {
        unmap_file(options->infile, filesize);
        return NULL; /* FAILED */
    }
    msi_ctx = msi_ctx_get(options->indata, filesize);
    if (!msi_ctx) {
        unmap_file(options->infile, filesize);
        return NULL; /* FAILED */
    }
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    ctx->format = &file_format_msi;
    ctx->options = options;
    ctx->msi_ctx = msi_ctx;

    if (hash)
        BIO_push(hash, BIO_new(BIO_s_null()));

    if (options->pagehash == 1)
        printf("Warning: -ph option is only valid for PE files\n");
    if (options->jp >= 0)
        printf("Warning: -jp option is only valid for CAB files\n");
    return ctx;
}

/*
 * Allocate and return SpcSipInfo object.
 * [out] p: SpcSipInfo data
 * [out] plen: SpcSipInfo data length
 * [in] ctx: structure holds input and output data (unused)
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_SIPINFO_OBJID
 */
static ASN1_OBJECT *msi_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
    const u_char msistr[] = {
        0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };
    ASN1_OBJECT *dtype;
    SpcSipInfo *si = SpcSipInfo_new();

    /* squash the unused parameter warning */
    (void)ctx;

    ASN1_INTEGER_set(si->a, 1);
    ASN1_INTEGER_set(si->b, 0);
    ASN1_INTEGER_set(si->c, 0);
    ASN1_INTEGER_set(si->d, 0);
    ASN1_INTEGER_set(si->e, 0);
    ASN1_INTEGER_set(si->f, 0);
    ASN1_OCTET_STRING_set(si->string, msistr, sizeof msistr);
    *plen = i2d_SpcSipInfo(si, NULL);
    *p = OPENSSL_malloc((size_t)*plen);
    i2d_SpcSipInfo(si, p);
    *p -= *plen;
    dtype = OBJ_txt2obj(SPC_SIPINFO_OBJID, 1);
    SpcSipInfo_free(si);
    return dtype; /* OK */
}

/*
 * Get DigitalSignature and MsiDigitalSignatureEx streams,
 * check if the signature exists.
 * [in, out] ctx: structure holds input and output data
 * [in] detached: embedded/detached PKCS#7 signature switch (unused)
 * [returns] 0 on error or 1 on successs
 */
static int msi_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
    char *indata = NULL;
    uint32_t inlen;
    MSI_ENTRY *ds, *dse = NULL;

    /* squash the unused parameter warning */
    (void)detached;

    if (!ctx) {
        printf("Init error\n\n");
        return 0; /* FAILED */
    }
    if (detached) {
        printf("Checking the specified catalog file\n\n");
        return 1; /* OK */
    }
    ds = msi_signatures_get(ctx->msi_ctx->dirent, &dse);
    if (!ds) {
        printf("MSI file has no signature\n\n");
        return 0; /* FAILED */
    }
    inlen = GET_UINT32_LE(ds->size);
    if (inlen == 0 || inlen >= MAXREGSECT) {
        printf("Corrupted DigitalSignature stream length 0x%08X\n", inlen);
        return 0; /* FAILED */
    }
    indata = OPENSSL_malloc((size_t)inlen);
    if (!msi_file_read(ctx->msi_ctx->msi, ds, 0, indata, inlen)) {
        printf("DigitalSignature stream data error\n\n");
        OPENSSL_free(indata);
        return 0; /* FAILED */
    }
    if (!dse) {
        printf("Warning: MsiDigitalSignatureEx stream doesn't exist\n");
    } else {
        ctx->msi_ctx->len_msiex = GET_UINT32_LE(dse->size);
        if (ctx->msi_ctx->len_msiex == 0 || ctx->msi_ctx->len_msiex >= MAXREGSECT) {
            printf("Corrupted MsiDigitalSignatureEx stream length 0x%08X\n",
                ctx->msi_ctx->len_msiex);
            OPENSSL_free(indata);
            return 0; /* FAILED */
        }
        ctx->msi_ctx->p_msiex = OPENSSL_malloc((size_t)ctx->msi_ctx->len_msiex);
        if (!msi_file_read(ctx->msi_ctx->msi, dse, 0, (char *)ctx->msi_ctx->p_msiex,
                ctx->msi_ctx->len_msiex)) {
            printf("MsiDigitalSignatureEx stream data error\n\n");
            OPENSSL_free(indata);
            return 0; /* FAILED */
        }
    }
    OPENSSL_free(indata);
    return 1; /* OK */
}

/*
 * Compute a simple sha1/sha256 message digest of the MSI file
 * for use with a catalog file.
 * [in] ctx: structure holds input and output data
 * [in] md: message digest algorithm
 * [returns] pointer to calculated message digest
 */
static u_char *msi_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md)
{
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());

    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return NULL;  /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    if (!bio_hash_data(bhash, ctx->options->indata, 0, ctx->msi_ctx->fileend)) {
        printf("Unable to calculate digest\n");
        BIO_free_all(bhash);
        return NULL;  /* FAILED */
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char *)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    return mdbuf; /* OK */
}

/*
 * Calculate DigitalSignature and MsiDigitalSignatureEx and compare to values
 * retrieved from PKCS#7 signedData.
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int msi_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    int mdok, mdlen, mdtype = -1;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    u_char cmdbuf[EVP_MAX_MD_SIZE];
    u_char cexmdbuf[EVP_MAX_MD_SIZE];
    u_char *cdigest = NULL;
    const EVP_MD *md;
    BIO *hash;

    if (is_content_type(p7, SPC_INDIRECT_DATA_OBJID)) {
        ASN1_STRING *content_val = p7->d.sign->contents->d.other->value.sequence;
        const u_char *p = content_val->data;
        SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, content_val->length);
        if (idc) {
            if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
                mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
                memcpy(mdbuf, idc->messageDigest->digest->data, (size_t)idc->messageDigest->digest->length);
            }
            SpcIndirectDataContent_free(idc);
        }
    }
    if (mdtype == -1) {
        printf("Failed to extract current message digest\n\n");
        return 0; /* FAILED */
    }
    printf("Message digest algorithm         : %s\n", OBJ_nid2sn(mdtype));
    md = EVP_get_digestbynid(mdtype);
    hash = BIO_new(BIO_f_md());
    if (!BIO_set_md(hash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(hash);
        return 0; /* FAILED */
    }
    BIO_push(hash, BIO_new(BIO_s_null()));
    if (ctx->msi_ctx->p_msiex) {
        BIO *prehash = BIO_new(BIO_f_md());
        if (EVP_MD_size(md) != (int)ctx->msi_ctx->len_msiex) {
            printf("Incorrect MsiDigitalSignatureEx stream data length\n\n");
            BIO_free_all(hash);
            BIO_free_all(prehash);
            return 0; /* FAILED */
        }
        if (!BIO_set_md(prehash, md)) {
            printf("Unable to set the message digest of BIO\n");
            BIO_free_all(hash);
            BIO_free_all(prehash);
            return 0; /* FAILED */
        }
        BIO_push(prehash, BIO_new(BIO_s_null()));

        print_hash("Current MsiDigitalSignatureEx    ", "", (u_char *)ctx->msi_ctx->p_msiex,
            (int)ctx->msi_ctx->len_msiex);
        if (!msi_prehash_dir(ctx->msi_ctx->dirent, prehash, 1)) {
            printf("Failed to calculate pre-hash used for MsiDigitalSignatureEx\n\n");
            BIO_free_all(hash);
            BIO_free_all(prehash);
            return 0; /* FAILED */
        }
        BIO_gets(prehash, (char*)cexmdbuf, EVP_MAX_MD_SIZE);
        BIO_free_all(prehash);
        BIO_write(hash, (char*)cexmdbuf, EVP_MD_size(md));
        print_hash("Calculated MsiDigitalSignatureEx ", "", cexmdbuf, EVP_MD_size(md));
    }

    if (!msi_hash_dir(ctx->msi_ctx->msi, ctx->msi_ctx->dirent, hash, 1)) {
        printf("Failed to calculate DigitalSignature\n\n");
        BIO_free_all(hash);
        return 0; /* FAILED */
    }
    print_hash("Current DigitalSignature         ", "", mdbuf, EVP_MD_size(md));
    BIO_gets(hash, (char*)cmdbuf, EVP_MAX_MD_SIZE);
    BIO_free_all(hash);
    mdok = !memcmp(mdbuf, cmdbuf, (size_t)EVP_MD_size(md));
    print_hash("Calculated DigitalSignature      ", mdok ? "" : "    MISMATCH!!!\n",
        cmdbuf, EVP_MD_size(md));
    if (!mdok) {
        printf("Signature verification: failed\n\n");
        return 0; /* FAILED */
    }
    cdigest = msi_digest_calc(ctx, md);
    if (!cdigest) {
        printf("Failed to calculate simple message digest\n\n");
        return 0; /* FAILED */
    }
    mdlen = EVP_MD_size(EVP_get_digestbynid(mdtype));
    print_hash("Calculated message digest        ", "\n", cdigest, mdlen);
    OPENSSL_free(cdigest);
    return 1; /* OK */
}

/*
 * Extract existing signature in DER format.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *msi_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
    PKCS7 *p7;
    uint32_t len;
    char *p;

    MSI_ENTRY *ds = msi_signatures_get(ctx->msi_ctx->dirent, NULL);
    if (!ds) {
        return NULL; /* FAILED */
    }
    len = GET_UINT32_LE(ds->size);
    if (len == 0 || len >= MAXREGSECT) {
        printf("Corrupted DigitalSignature stream length 0x%08X\n", len);
        return NULL; /* FAILED */
    }
    p = OPENSSL_malloc((size_t)len);
    p7 = msi_pkcs7_get_digital_signature(ctx, ds, &p, len);
    OPENSSL_free(p);
    return p7;
}

/*
 * Remove existing signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int msi_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    /* squash the unused parameter warning */
    (void)hash;

    if (!msi_dirent_delete(ctx->msi_ctx->dirent, digital_signature_ex,
            sizeof digital_signature_ex)) {
        return 1; /* FAILED */
    }
    if (!msi_dirent_delete(ctx->msi_ctx->dirent, digital_signature,
            sizeof digital_signature)) {
        return 1; /* FAILED */
    }
    if (!msi_file_write(ctx->msi_ctx->msi, ctx->msi_ctx->dirent,
            NULL, 0, NULL, 0, outdata)) {
        printf("Saving the msi file failed\n");
        return 1; /* FAILED */
    }
    return 0; /* OK */
}

/*
 * Obtain an existing signature or create a new one.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO (unused)
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *msi_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    PKCS7 *cursig = NULL, *p7 = NULL;
    uint32_t len;
    char *p;

    /* squash the unused parameter warning */
    (void)outdata;

    if (ctx->options->add_msi_dse && !msi_calc_MsiDigitalSignatureEx(ctx, hash)) {
        printf("Unable to calc MsiDigitalSignatureEx\n");
        return NULL; /* FAILED */
    }
    if (!msi_hash_dir(ctx->msi_ctx->msi, ctx->msi_ctx->dirent, hash, 1)) {
        printf("Unable to msi_handle_dir()\n");
        return NULL; /* FAILED */
    }
    /* Obtain a current signature from previously-signed file */
    if ((ctx->options->cmd == CMD_SIGN && ctx->options->nest)
        || (ctx->options->cmd == CMD_ATTACH && ctx->options->nest)
        || ctx->options->cmd == CMD_ADD) {
        MSI_ENTRY *dse = NULL;
        MSI_ENTRY *ds = msi_signatures_get(ctx->msi_ctx->dirent, &dse);
        if (!ds) {
            printf("MSI file has no signature\n\n");
            return NULL; /* FAILED */
        }
        if (!msi_check_MsiDigitalSignatureEx(ctx, dse)) {
            return NULL; /* FAILED */
        }
        len = GET_UINT32_LE(ds->size);
        if (len == 0 || len >= MAXREGSECT) {
            printf("Corrupted DigitalSignature stream length 0x%08X\n", len);
            return NULL; /* FAILED */
        }
        p = OPENSSL_malloc((size_t)len);
        /* get current signature */
        cursig = msi_pkcs7_get_digital_signature(ctx, ds, &p, len);
        OPENSSL_free(p);
        if (!cursig) {
            printf("Unable to extract existing signature\n");
            return NULL; /* FAILED */
        }
        if (ctx->options->cmd == CMD_ADD)
            p7 = cursig;
    }
    if (ctx->options->cmd == CMD_ATTACH) {
        /* Obtain an existing PKCS#7 signature */
        p7 = pkcs7_get_sigfile(ctx);
        if (!p7) {
            printf("Unable to extract valid signature\n");
            PKCS7_free(cursig);
            return NULL; /* FAILED */
        }
    } else if (ctx->options->cmd == CMD_SIGN) {
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
    if (ctx->options->nest)
        ctx->options->prevsig = cursig;
    return p7;
}

/*
 * Append signature to the outfile.
 * [in, out] ctx: structure holds input and output data
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int msi_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    u_char *p = NULL;
    int len;         /* signature length */

    if (((len = i2d_PKCS7(p7, NULL)) <= 0)
        || (p = OPENSSL_malloc((size_t)len)) == NULL) {
        printf("i2d_PKCS memory allocation failed: %d\n", len);
        return 1; /* FAILED */
    }
    i2d_PKCS7(p7, &p);
    p -= len;

    if (!msi_file_write(ctx->msi_ctx->msi, ctx->msi_ctx->dirent, p, (uint32_t)len,
        ctx->msi_ctx->p_msiex, ctx->msi_ctx->len_msiex, outdata)) {
        printf("Saving the msi file failed\n");
        OPENSSL_free(p);
        return 1; /* FAILED */
    }
    OPENSSL_free(p);
    return 0; /* OK */
}

/*
 * Free up an entire outdata BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] none
 */
static BIO *msi_bio_free(BIO *hash, BIO *outdata)
{
    BIO_free_all(hash);
    BIO_free_all(outdata);
    return NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and MSI format specific structures,
 * unmap indata file, unlink outfile.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] none
 */
static void msi_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (outdata) {
        BIO_free_all(hash);
        BIO_free_all(outdata);
        if (ctx->options->outfile) {
#ifdef WIN32
            _unlink(ctx->options->outfile);
#else
            unlink(ctx->options->outfile);
#endif /* WIN32 */
        }
    }
    unmap_file(ctx->options->indata, ctx->msi_ctx->fileend);
    msi_file_free(ctx->msi_ctx->msi);
    msi_dirent_free(ctx->msi_ctx->dirent);
    OPENSSL_free(ctx->msi_ctx->p_msiex);
    OPENSSL_free(ctx->msi_ctx);
    OPENSSL_free(ctx);
}

/*
 * MSI helper functions
 */

/*
 * Verify mapped MSI file and create MSI format specific structure.
 * [in] indata: mapped MSI file
 * [in] filesize: size of MSI file
 * [returns] pointer to MSI format specific structure
 */
static MSI_CTX *msi_ctx_get(char *indata, uint32_t filesize)
{
    MSI_ENTRY *root;
    MSI_FILE *msi;
    MSI_DIRENT *dirent;
    MSI_CTX *msi_ctx;

    msi = msi_file_new(indata, filesize);
    if (!msi) {
        printf("Failed to parse MSI_FILE struct\n");
        return NULL; /* FAILED */
    }
    root = msi_root_entry_get(msi);
    if (!root) {
        printf("Failed to get file entry\n");
        msi_file_free(msi);
        return NULL; /* FAILED */
    }
    if (!msi_dirent_new(msi, root, NULL, &(dirent))) {
        printf("Failed to parse MSI_DIRENT struct\n");
        msi_file_free(msi);
        return NULL; /* FAILED */
    }
    msi_ctx = OPENSSL_zalloc(sizeof(MSI_CTX));
    msi_ctx->msi = msi;
    msi_ctx->dirent = dirent;
    msi_ctx->fileend = filesize;
    return msi_ctx; /* OK */
}

static PKCS7 *msi_pkcs7_get_digital_signature(FILE_FORMAT_CTX *ctx, MSI_ENTRY *ds,
    char **p, uint32_t len)
{
    PKCS7 *p7 = NULL;
    const u_char *blob;

    if (!msi_file_read(ctx->msi_ctx->msi, ds, 0, *p, len)) {
        printf("DigitalSignature stream data error\n");
        return NULL;
    }
    blob = (u_char *)*p;
    p7 = d2i_PKCS7(NULL, &blob, len);
    if (!p7) {
        printf("Failed to extract PKCS7 data\n");
        return NULL;
    }
    return p7;
}

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
    uint32_t entriesPerSector, difatSectorLocation, fatSectorLocation;
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
        fatSectorLocation = GET_UINT32_LE(address);
        if (fatSectorLocation == 0 || fatSectorLocation >= FREESECT) {
            printf("Get corrupted sector location 0x%08X\n", fatSectorLocation);
            return NOSTREAM; /* FAILED */
        }
        return fatSectorLocation;
    }
}

/* Lookup FAT */
static uint32_t get_next_sector(MSI_FILE *msi, uint32_t sector)
{
    const u_char *address;
    uint32_t nextSectorLocation;
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
    nextSectorLocation = GET_UINT32_LE(address);
    if (nextSectorLocation == 0 || nextSectorLocation >= FREESECT) {
        printf("Get corrupted sector location 0x%08X\n", nextSectorLocation);
        return NOSTREAM; /* FAILED */
    }
    return nextSectorLocation;
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
    uint32_t sector, offset, nextMiniSectorLocation;
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
    nextMiniSectorLocation = GET_UINT32_LE(address);
    if (nextMiniSectorLocation == 0 || nextMiniSectorLocation >= FREESECT) {
        printf("Get corrupted sector location 0x%08X\n", nextMiniSectorLocation);
        return NOSTREAM; /* FAILED */
    }
    return nextMiniSectorLocation;
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
static int msi_file_read(MSI_FILE *msi, MSI_ENTRY *entry, uint32_t offset, char *buffer, uint32_t len)
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
    if (is_root && (entry->nameLen != sizeof msi_root_entry
        || memcmp(entry->name, msi_root_entry, entry->nameLen))) {
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

static MSI_ENTRY *msi_root_entry_get(MSI_FILE *msi)
{
    return get_entry(msi, 0, TRUE);
}

static void msi_file_free(MSI_FILE *msi)
{
    if (!msi)
        return;
    OPENSSL_free(msi->m_hdr);
    OPENSSL_free(msi);
}

/* Parse MSI_FILE struct */
static MSI_FILE *msi_file_new(char *buffer, uint32_t len)
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
static int msi_dirent_new(MSI_FILE *msi, MSI_ENTRY *entry, MSI_DIRENT *parent, MSI_DIRENT **ret)
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
static MSI_ENTRY *msi_signatures_get(MSI_DIRENT *dirent, MSI_ENTRY **dse)
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

/* Recursively free MSI_DIRENT struct */
static void msi_dirent_free(MSI_DIRENT *dirent)
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
static int msi_prehash_dir(MSI_DIRENT *dirent, BIO *hash, int is_root)
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
static int msi_hash_dir(MSI_FILE *msi, MSI_DIRENT *dirent, BIO *hash, int is_root)
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
            /* Skip DigitalSignature and MsiDigitalSignatureEx streams */
            continue;
        }
        if (child->type == DIR_STREAM) {
            char *indata;
            uint32_t inlen = GET_UINT32_LE(child->entry->size);
            if (inlen == 0 || inlen >= MAXREGSECT) {
                /* Skip null and corrupted streams */
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

static int msi_dirent_delete(MSI_DIRENT *dirent, const u_char *name, uint16_t nameLen)
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
        /* DigitalSignature */
        inlen = len_msi;
        *indata = OPENSSL_malloc((size_t)inlen);
        memcpy(*indata, p_msi, (size_t)inlen);
    } else if (is_root && !memcmp(entry->name, digital_signature_ex, sizeof digital_signature_ex)) {
        /* MsiDigitalSignatureEx */
        inlen = len_msiex;
        *indata = OPENSSL_malloc((size_t)inlen);
        memcpy(*indata, p_msiex, (size_t)inlen);
    } else if (inlen != 0) {
        *indata = (char *)OPENSSL_malloc(inlen);
        if (!msi_file_read(msi, entry, 0, *indata, inlen)) {
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
            char buf[MAX_SECTOR_SIZE];
            char *indata = NULL;
            uint32_t inlen = GET_UINT32_LE(child->entry->size);
            if (inlen >= MAXREGSECT) {
                printf("Corrupted stream length 0x%08X\n", inlen);
                return 0; /* FAILED */
            }
            /* DigitalSignature or MsiDigitalSignatureEx: inlen == 0 */
            inlen = stream_read(msi, child->entry, p_msi, len_msi, p_msiex, len_msiex, &indata, inlen, is_root);
            if (inlen == 0) {
                printf("Failed to read stream data\n");
                OPENSSL_free(indata);
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

static void fat_pad_last_sector(MSI_OUT *out, int padValue, char *buf)
{
    if (out->fatLen % out->sectorSize > 0) {
        uint32_t remain = out->sectorSize - out->fatLen % out->sectorSize;
        memset(buf, padValue, (size_t)remain);
        fat_append(out, buf, remain);
    }
}

static int fat_save(BIO *outdata, MSI_OUT *out)
{
    char buf[MAX_SECTOR_SIZE];
    uint32_t i, j, remain, difatSectors, difatEntriesPerSector, fatSectorIndex, lastFatSectorIndex;

    remain = (out->fatLen + out->sectorSize - 1) / out->sectorSize;
    out->fatSectorsCount = (out->fatLen + remain * 4 + out->sectorSize - 1) / out->sectorSize;

    fat_pad_last_sector(out, 0, buf);

    if (out->fatSectorsCount > DIFAT_IN_HEADER) {
        difatEntriesPerSector = (out->sectorSize / 4) - 1;
        difatSectors = (out->fatSectorsCount - DIFAT_IN_HEADER + difatEntriesPerSector - 1) / difatEntriesPerSector;
    } else {
        difatSectors = 0;
    }

    /* set 109 FAT sectors in HEADER_DIFAT table */
    for (i = 0; i < MIN(out->fatSectorsCount, DIFAT_IN_HEADER); i++) {
        PUT_UINT32_LE(out->sectorNum + i, buf);
        memcpy(out->header + HEADER_DIFAT + i * 4, buf, 4);
    }
    out->sectorNum += out->fatSectorsCount;

    if (out->fatSectorsCount > DIFAT_IN_HEADER) {
        /* Set DIFAT start sector number in header */
        PUT_UINT32_LE(out->sectorNum, buf);
        memcpy(out->header + HEADER_DIFAT_SECTOR_LOC, buf, 4);

        /* Set total DIFAT sectors number in header */
        PUT_UINT32_LE(difatSectors, buf);
        memcpy(out->header + HEADER_DIFAT_SECTORS_NUM, buf, 4);

        remain = out->fatSectorsCount - DIFAT_IN_HEADER;
        fatSectorIndex = out->sectorNum - remain;
        lastFatSectorIndex = out->sectorNum;

        /* Fill DIFAT sectors */
        for (i = 0; i < difatSectors; i++) {
            for (j = 0; j < difatEntriesPerSector; j++, fatSectorIndex++) {
                if (fatSectorIndex < lastFatSectorIndex) {
                    PUT_UINT32_LE(fatSectorIndex, buf + j * 4);
                } else {
                    PUT_UINT32_LE(FREESECT, buf + j * 4);
                }
            }

            /* Add next DIFAT sector link or mark end of chain */
            if (i + 1 >= difatSectors) {
                PUT_UINT32_LE(ENDOFCHAIN, buf + out->sectorSize - 4);
            } else {
                PUT_UINT32_LE(out->sectorNum + 1, buf + out->sectorSize - 4);
            }

            fat_append(out, buf, out->sectorSize);
            out->sectorNum++;
        }
    }

    /* mark FAT sectors in the FAT chain */
    PUT_UINT32_LE(FATSECT, buf);
    for (i=0; i<out->fatSectorsCount; i++) {
        fat_append(out, buf, 4);
    }

    /* mark DIFAT sectors in the FAT chain */
    PUT_UINT32_LE(DIFSECT, buf);
    for (i = 0; i < difatSectors; i++) {
        fat_append(out, buf, 4);
    }

    /* empty unallocated free sectors in the last FAT sector */
    fat_pad_last_sector(out, (int)FREESECT, buf);

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

static int msi_file_write(MSI_FILE *msi, MSI_DIRENT *dirent, u_char *p_msi, uint32_t len_msi,
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
 * MsiDigitalSignatureEx is an enhanced signature type that
 * can be used when signing MSI files.  In addition to
 * file content, it also hashes some file metadata, specifically
 * file names, file sizes, creation times and modification times.
 *
 * The file content hashing part stays the same, so the
 * msi_handle_dir() function can be used across both variants.
 *
 * When an MsiDigitalSigntaureEx section is present in an MSI file,
 * the meaning of the DigitalSignature section changes:  Instead
 * of being merely a file content hash (as what is output by the
 * msi_handle_dir() function), it is now hashes both content
 * and metadata.
 *
 * Here is how it works:
 *
 * First, a "pre-hash" is calculated. This is the "metadata" hash.
 * It iterates over the files in the MSI in the same order as the
 * file content hashing method would - but it only processes the
 * metadata.
 *
 * Once the pre-hash is calculated, a new hash is created for
 * calculating the hash of the file content.  The output of the
 * pre-hash is added as the first element of the file content hash.
 *
 * After the pre-hash is written, what follows is the "regular"
 * stream of data that would normally be written when performing
 * file content hashing.
 *
 * The output of this hash, which combines both metadata and file
 * content, is what will be output in signed form to the
 * DigitalSignature section when in 'MsiDigitalSignatureEx' mode.
 *
 * As mentioned previously, this new mode of operation is signalled
 * by the presence of a 'MsiDigitalSignatureEx' section in the MSI
 * file.  This section must come after the 'DigitalSignature'
 * section, and its content must be the output of the pre-hash
 * ("metadata") hash.
 */

static int msi_calc_MsiDigitalSignatureEx(FILE_FORMAT_CTX *ctx, BIO *hash)
{
    size_t written;
    BIO *prehash = BIO_new(BIO_f_md());

    if (!BIO_set_md(prehash, ctx->options->md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(prehash);
        return 0; /* FAILED */
    }
    BIO_push(prehash, BIO_new(BIO_s_null()));

    if (!msi_prehash_dir(ctx->msi_ctx->dirent, prehash, 1)) {
        printf("Unable to calculate MSI pre-hash ('metadata') hash\n");
        return 0; /* FAILED */
    }
    ctx->msi_ctx->p_msiex = OPENSSL_malloc(EVP_MAX_MD_SIZE);
    ctx->msi_ctx->len_msiex = (uint32_t)BIO_gets(prehash,
        (char *)ctx->msi_ctx->p_msiex, EVP_MAX_MD_SIZE);
    if (!BIO_write_ex(hash, ctx->msi_ctx->p_msiex, ctx->msi_ctx->len_msiex, &written)
        || written != ctx->msi_ctx->len_msiex)
        return 0; /* FAILED */
    BIO_free_all(prehash);
    return 1; /* OK */
}

/*
 * Perform a sanity check for the MsiDigitalSignatureEx section.
 * If the file we're attempting to sign has an MsiDigitalSignatureEx
 * section, we can't add a nested signature of a different MD type
 * without breaking the initial signature.
 */
static int msi_check_MsiDigitalSignatureEx(FILE_FORMAT_CTX *ctx, MSI_ENTRY *dse)
{
    if (dse && GET_UINT32_LE(dse->size) != (uint32_t)EVP_MD_size(ctx->options->md)) {
        printf("Unable to add nested signature with a different MD type (-h parameter) "
            "than what exists in the MSI file already.\nThis is due to the presence of "
            "MsiDigitalSignatureEx (-add-msi-dse parameter).\n\n");
            return 0; /* FAILED */
    }
    if (!dse && ctx->options->add_msi_dse) {
        printf("Unable to add signature with -add-msi-dse parameter "
            "without breaking the initial signature.\n\n");
            return 0; /* FAILED */
    }
    if (dse && !ctx->options->add_msi_dse) {
        printf("Unable to add signature without -add-msi-dse parameter "
            "without breaking the initial signature.\nThis is due to the presence of "
            "MsiDigitalSignatureEx (-add-msi-dse parameter).\n"
            "Should use -add-msi-dse options in this case.\n\n");
            return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: nil
End:

  vim: set ts=4 expandtab:
*/
