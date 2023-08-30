/*
 * APPX file support library
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 *
 * Copyright (C) Maciej Panek <maciej.panek_malpa_punxworks.com>
 * Copyright (C) 2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 */

#define _FILE_OFFSET_BITS 64

#include "osslsigncode.h"
#include "helpers.h"

#include <zlib.h> /* crc32() */
#include <inttypes.h>

#if defined(_MSC_VER)
#define fseeko _fseeki64
#define ftello _ftelli64
#endif

#define EOCDR_SIZE 22
#define ZIP64_EOCD_LOCATOR_SIZE 20
#define ZIP64_HEADER 0x01
#define COMPRESSION_NONE 0
#define COMPRESSION_DEFLATE 8
#define DATA_DESCRIPTOR_BIT (1 << 3)

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

static const char *HASH_METHOD_TAG = "HashMethod";
static const char *HASH_METHOD_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
static const char *HASH_METHOD_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
static const char *HASH_METHOD_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

/*
 * Overall .ZIP file format:
 *
 * [local file header 1]
 * [encryption header 1]
 * [file data 1]
 * [data descriptor 1]
 * .
 * .
 * .
 * [local file header n]
 * [encryption header n]
 * [file data n]
 * [data descriptor n]
 * [archive decryption header]
 * [archive extra data record]
 * [central directory header 1]
 * .
 * .
 * .
 * [central directory header n]
 * [zip64 end of central directory record]
 * [zip64 end of central directory locator]
 * [end of central directory record]
 */

/* Local file header */
typedef struct {
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
    int compressedSizeInZip64;
    int uncompressedSizeInZip64;
} ZIP_LOCAL_HEADER;

/* Data descriptor */
typedef struct {
    uint32_t crc32;
    uint64_t compressedSize;
    uint64_t uncompressedSize;
    uint8_t *data;
} ZIP_OVERRIDE_DATA;

/* Central directory structure */
typedef struct zipCentralDirectoryEntry_struct {
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
    int compressedSizeInZip64;
    int uncompressedSizeInZip64;
    int offsetInZip64;
    int diskNoInZip64;
    ZIP_OVERRIDE_DATA *overrideData;
    struct zipCentralDirectoryEntry_struct *next;
} ZIP_CENTRAL_DIRECTORY_ENTRY;

/* Zip64 end of central directory record */
typedef struct {
    uint64_t eocdrSize;
    uint16_t creatorVersion;
    uint16_t viewerVersion;
    uint32_t diskNumber;
    uint32_t diskWithCentralDirectory;
    uint64_t diskEntries;
    uint64_t totalEntries;
    uint64_t centralDirectorySize;
    uint64_t centralDirectoryOffset;
    uint64_t commentLen;
    char *comment;
} ZIP64_EOCDR;

/* Zip64 end of central directory locator */
typedef struct {
    uint32_t diskWithEOCD;
    uint64_t eocdOffset;
    uint32_t totalNumberOfDisks;
} ZIP64_EOCD_LOCATOR;

/* End of central directory record */
typedef struct {
    uint16_t diskNumber;
    uint16_t centralDirectoryDiskNumber;
    uint16_t diskEntries;
    uint16_t totalEntries;
    uint32_t centralDirectorySize;
    uint32_t centralDirectoryOffset;
    uint16_t commentLen;
    char *comment;
} ZIP_EOCDR;

typedef struct {
    FILE *file;
    ZIP_CENTRAL_DIRECTORY_ENTRY *centralDirectoryHead;
    uint64_t centralDirectorySize;
    uint64_t centralDirectoryOffset;
    uint64_t centralDirectoryRecordCount;
    uint64_t eocdrOffset;
    int64_t eocdrLen;
    int64_t fileSize;
    int isZip64;
    /* this will come handy to rewrite the eocdr */
    ZIP_EOCDR eocdr;
    ZIP64_EOCD_LOCATOR locator;
    ZIP64_EOCDR eocdr64;
} ZIP_FILE;

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

struct appx_ctx_st {
    ZIP_FILE *zip;
    u_char *calculatedBMHash;
    u_char *calculatedCTHash;
    u_char *calculatedCDHash;
    u_char *calculatedDataHash;
    u_char *calculatedCIHash;
    u_char *existingBMHash;
    u_char *existingCTHash;
    u_char *existingCDHash;
    u_char *existingDataHash;
    u_char *existingCIHash;
    int isBundle;
    const EVP_MD *md;
} appx_ctx_t;

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

/* see helpers.c */
static int appx_pkcs7_set_spc_indirect_data_content(PKCS7 *p7, u_char *hash, int hashLen, u_char *buf, int len);
static int appx_spc_indirect_data_content_get(u_char **blob, int *len, FILE_FORMAT_CTX *ctx, int hashLen);
static int appx_pkcs7_set_data_content(PKCS7 *p7, u_char *hash, int hashLen, FILE_FORMAT_CTX *ctx);
static int appx_add_indirect_data_object(PKCS7 *p7, u_char *hash, int hashLen, FILE_FORMAT_CTX *ctx);


/* Prototypes */
static u_char *appx_hash_blob_get(FILE_FORMAT_CTX *ctx, int *plen);
static int appx_calculate_hashes(FILE_FORMAT_CTX *ctx);
static uint8_t *appx_calc_zip_central_directory_hash(ZIP_FILE *zip, const EVP_MD *md, uint64_t cdOffset);
static void appx_write_central_directory(ZIP_FILE *zip, BIO *bio, int removeSignature, uint64_t cdOffset);
static uint8_t *appx_calc_zip_data_hash(ZIP_FILE *zip, const EVP_MD *md, uint64_t *cdOffset);
static int appx_extract_hashes(FILE_FORMAT_CTX *ctx, SpcIndirectDataContent *content);
static int appx_compare_hashes(FILE_FORMAT_CTX *ctx);
static int appx_remove_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static int appx_append_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static const EVP_MD *appx_get_md(ZIP_FILE *zip);
static ZIP_CENTRAL_DIRECTORY_ENTRY *zipGetCDEntryByName(ZIP_FILE *zip, const char *name);
static void zipWriteCentralDirectoryEntry(BIO *bio, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint64_t offsetDiff, uint64_t *sizeOnDisk);
static int zipAppendFile(ZIP_FILE *zip, BIO *bio, const char *fn, uint8_t *data, uint64_t dataSize, int comprs);
static int zipOverrideFileData(ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint8_t *data, uint64_t dataSize, int comprs);
static int zipRewriteData(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, BIO *bio, uint64_t *sizeOnDisk);
static void zipWriteLocalHeader(BIO *bio, ZIP_LOCAL_HEADER *header, uint64_t *sizeonDisk);
static int zipEntryExist(ZIP_FILE *zip, const char *name);
static u_char *zipCalcDigest(ZIP_FILE *zip, const char *fileName, const EVP_MD *md);
static int zipReadFileDataByName(ZIP_FILE *zip, const char *name, uint8_t **pData, uint64_t *dataSize, int unpack);
static int zipReadFileData(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint8_t **pData, uint64_t *dataSize, int unpack);
static int zipReadLocalHeader(ZIP_LOCAL_HEADER *header, ZIP_FILE *zip, uint64_t compressedSize);
static int zipInflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong *sourceLen);
static int zipDeflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong sourceLen, int level);
static ZIP_FILE *openZip(const char *fn);
static void freeZip(ZIP_FILE *zip);
static void zipPrintCentralDirectory(ZIP_FILE *zip);
static int zipReadCentralDirectory(ZIP_FILE *zip, FILE *file);
static ZIP_CENTRAL_DIRECTORY_ENTRY *zipReadNextCentralDirectoryEntry(FILE *file);
static void freeZipCentralDirectoryEntry(ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static int readZipEOCDR(ZIP_EOCDR *eocdr, FILE *file);
static int readZip64EOCDLocator(ZIP64_EOCD_LOCATOR *locator, FILE *file);
static int readZip64EOCDR(ZIP64_EOCDR *eocdr, FILE *file, uint64_t offset);
static uint64_t fileGetU64(FILE *file);
static uint32_t fileGetU32(FILE *file);
static uint16_t fileGetU16(FILE *file);
static uint64_t bufferGetU64(uint8_t *buffer, uint64_t *pos);
static uint32_t bufferGetU32(uint8_t *buffer, uint64_t *pos);
static uint16_t bufferGetU16(uint8_t *buffer, uint64_t *pos);
static void bioAddU64(BIO *bio, uint64_t v);
static void bioAddU32(BIO *bio, uint32_t v);
static void bioAddU16(BIO *bio, uint16_t v);


/*
 * FILE_FORMAT method definitions
 */

/*
 * Allocate and return a PE file format context.
 * [in, out] options: structure holds the input data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] pointer to PE file format context
 */
static FILE_FORMAT_CTX *appx_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
    FILE_FORMAT_CTX *ctx;
    const EVP_MD *md;
    ZIP_FILE *zip = openZip(options->infile);

    /* squash unused parameter warnings */
    (void)hash;
    (void)outdata;

    if (!zip) {
        return NULL; /* FAILED */
    }
    if (options->verbose) {
        zipPrintCentralDirectory(zip);
    }
    md = appx_get_md(zip);
    if (!md) {
        freeZip(zip);
        return NULL; /* FAILED */
    }
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    ctx->appx_ctx = OPENSSL_zalloc(sizeof(appx_ctx_t));
    ctx->appx_ctx->zip = zip;
    ctx->format = &file_format_appx;
    ctx->options = options;
    ctx->appx_ctx->md = md;
    if (zipGetCDEntryByName(zip, APPXBUNDLE_MANIFEST_FILE_NAME)) {
        ctx->appx_ctx->isBundle = 1;
    }
    return ctx;
}

/*
 * Allocate and return SpcSipInfo object.
 * [out] p: SpcSipInfo data
 * [out] plen: SpcSipInfo data length
 * [in] ctx: structure holds input and output data (unused)
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_SIPINFO_OBJID
 */
static ASN1_OBJECT *appx_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
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

    if (ctx->appx_ctx->isBundle) {
        printf("Signing as a bundle\n");
        ASN1_OCTET_STRING_set(si->string, APPXBUNDLE_UUID, sizeof(APPXBUNDLE_UUID));
    } else {
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
 * Print current and calculated PE checksum, (unsupported)
 * check if the signature exists.
 * [in, out] ctx: structure holds input and output data
 * [in] detached: embedded/detached PKCS#7 signature switch
 * [returns] 0 on error or 1 on success
 */
static int appx_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
    if (detached) {
        printf("APPX does not support detached option\n");
        return 0; /* FAILED */
    }
    appx_calculate_hashes(ctx);
    if (!zipEntryExist(ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME)) {
        printf("%s does not exist\n", APP_SIGNATURE_FILENAME);
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Calculate message digest and page_hash and compare to values retrieved
 * from PKCS#7 signedData.
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int appx_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    if (is_content_type(p7, SPC_INDIRECT_DATA_OBJID)) {
        ASN1_STRING *content_val = p7->d.sign->contents->d.other->value.sequence;
        const u_char *p = content_val->data;
        SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, content_val->length);

        if (idc) {
            if (!appx_extract_hashes(ctx, idc)) {
                printf("Failed to extract hashes from the signature\n");
                SpcIndirectDataContent_free(idc);
                return 0; /* FAILED */
            }
            if (!appx_calculate_hashes(ctx)) {
                printf("Failed to calculate one or more hash\n");
                SpcIndirectDataContent_free(idc);
                return 0; /* FAILED */
            }

            if (!appx_compare_hashes(ctx)) {
                printf("Signature hash verification failed\n");
                SpcIndirectDataContent_free(idc);
                return 0; /* FAILED */
            }
            SpcIndirectDataContent_free(idc);
        }
    }
    return 1; /* OK */
}

/*
 * Extract existing signature in DER format.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *appx_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
    PKCS7 *p7;
    uint8_t *data = NULL;
    const u_char *blob;
    uint64_t dataSize = 0;

    if (!zipReadFileDataByName(ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME, &data, &dataSize, 1)) {
        return NULL; /* FAILED */
    }
    if (memcmp(data, PKCX_SIGNATURE, 4)) {
        printf("Invalid PKCX header\n");
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    blob = (u_char *)data + 4;
    p7 = d2i_PKCS7(NULL, &blob, (int)dataSize - 4);
    OPENSSL_free(data);
    return p7;
}

/*
 * Remove existing signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int appx_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    uint64_t cdOffset;
    ZIP_FILE *zip = ctx->appx_ctx->zip;
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry = zipGetCDEntryByName(zip, CONTENT_TYPES_FILENAME);

    /* squash the unused parameter warning */
    (void)hash;

    if (!entry) {
        printf("Not a valid .appx file: content types file missing\n");
        return 1; /* FAILED */
    }
    if (!appx_remove_ct_signature_entry(zip, entry)) {
        return 1; /* FAILED */
    }
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (strcmp(APP_SIGNATURE_FILENAME, entry->fileName)) {
            uint64_t dummy;
            if (!zipRewriteData(zip, entry, outdata, &dummy)) {
                return 1; /* FAILED */
            }
        }
    }
    cdOffset = (uint64_t)BIO_tell(outdata);
    appx_write_central_directory(zip, outdata, 1, cdOffset);
    return 0; /* OK */
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

    if (ctx->options->cmd == CMD_ADD || ctx->options->cmd == CMD_ATTACH) {
        /* Obtain an existing signature */
        cursig = appx_pkcs7_extract(ctx);
        if (!cursig) {
            printf("Unable to extract existing signature\n");
            return NULL; /* FAILED */
        }
        return cursig;
    } else if (ctx->options->cmd == CMD_SIGN) {
        int len = 0;
        u_char *hashBlob;
        ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

        /* Create a new signature */
        entry = zipGetCDEntryByName(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME);
        if (!entry) {
            printf("Not a valid .appx file: content types file missing\n");
            return NULL; /* FAILED */
        }
        if (!appx_append_ct_signature_entry(ctx->appx_ctx->zip, entry)) {
            return NULL; /* FAILED */
        }
        if (!appx_calculate_hashes(ctx)) {
            printf("Failed to calculate one ore more hash\n");
            return NULL; /* FAILED */
        }
        /* Create a new PKCS#7 signature */
        p7 = pkcs7_create(ctx);
        if (!p7) {
            printf("Creating a new signature failed\n");
            return NULL; /* FAILED */
        }
        hashBlob = appx_hash_blob_get(ctx, &len);
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

/*
 * Append signature to the outfile.
 * [in, out] ctx: structure holds input and output data
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int appx_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    ZIP_FILE *zip = ctx->appx_ctx->zip;
    ZIP_CENTRAL_DIRECTORY_ENTRY *prev = NULL;
    ZIP_CENTRAL_DIRECTORY_ENTRY *last = NULL;
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    u_char *blob, *der = NULL;
    int len;
    uint64_t cdOffset;

    for (entry = zip->centralDirectoryHead; entry != NULL;) {
        last = entry;
        if (strcmp(APP_SIGNATURE_FILENAME, entry->fileName)) {
            uint64_t dummy = 0;
            if (!zipRewriteData(zip, entry, outdata, &dummy)) {
                return 1; /* FAILED */
            }
            prev = entry;
            entry = entry->next;
        } else {
            /* remove the entry
             * actually this code is pretty naive - if you remove the entry that was not at the end
             * everything will go south - the offsets in the CD will not match the local header offsets.
             * that can be fixed here or left as is - signtool and this tool always appends the signature file at the end.
             * Might be a problem when someone decides to unpack & repack the .appx zip file */
            ZIP_CENTRAL_DIRECTORY_ENTRY *current = entry;
            entry = entry->next;
            if (prev) {
                prev->next = entry;
            }
            freeZipCentralDirectoryEntry(current);
        }
    }
    if (!last) {
        /* not really possible unless an empty zip file, but who knows */
        return 1; /* FAILED */
    }
    /* create the signature entry */
    if (((len = i2d_PKCS7(p7, NULL)) <= 0) ||
        (der = OPENSSL_malloc((size_t)len)) == NULL)
        return 1; /* FAILED */
    i2d_PKCS7(p7, &der);
    der -= len;
    blob = OPENSSL_malloc((size_t)(len + 4));
    memcpy(blob, PKCX_SIGNATURE, 4);
    memcpy(blob + 4, der, (size_t)len);
    len += 4;
    if (!zipAppendFile(zip, outdata, APP_SIGNATURE_FILENAME, blob, (uint64_t)len, 1)) {
        OPENSSL_free(blob);
        printf("Failed to append zip file\n");
        return 1; /* FAILED */
    }
    OPENSSL_free(der);
    OPENSSL_free(blob);
    /* again, 32bit api -> will limit us to 2GB files */
    cdOffset = (uint64_t)BIO_tell(outdata);
    appx_write_central_directory(zip, outdata, 0, cdOffset);
    return 0; /* OK */
}

/*
 * Free up an entire message digest BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] none
 */
static BIO *appx_bio_free(BIO *hash, BIO *outdata)
{
    BIO_free_all(outdata);
    BIO_free_all(hash);
    return NULL; /* OK */
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and PE format specific structure,
 * unmap indata file, unlink outfile.
 * [out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] none
 */
static void appx_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    /* squash unused parameter warnings */
    (void)hash;
    (void)outdata;

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

/********************* helpers.c ****************************************/
/*
 * pkcs7_set_spc_indirect_data_content()
 * Replace the data part with the MS Authenticode spcIndirectDataContent blob
 * [out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [in] blob: SpcIndirectDataContent data
 * [in] len: SpcIndirectDataContent data length
 * [returns] 0 on error or 1 on success
 */
static int appx_pkcs7_set_spc_indirect_data_content(PKCS7 *p7, u_char *hash, int hashLen, u_char *buf, int len)
{
    int seqhdrlen;
    BIO *bio;
    PKCS7 *td7;

    memcpy(buf + len, hash, (size_t)hashLen);
    seqhdrlen = asn1_simple_hdr_len(buf, len);

    if ((bio = PKCS7_dataInit(p7, NULL)) == NULL) {
        printf("PKCS7_dataInit failed\n");
        return 0; /* FAILED */
    }

    BIO_write(bio, buf + seqhdrlen, len - seqhdrlen + hashLen);
    (void)BIO_flush(bio);

    if (!PKCS7_dataFinal(p7, bio)) {
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
 * spc_indirect_data_content_get()
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
    int mdtype = EVP_MD_nid(ctx->appx_ctx->md);

    SpcIndirectDataContent *idc = SpcIndirectDataContent_new();

    idc->data->value = ASN1_TYPE_new();
    idc->data->value->type = V_ASN1_SEQUENCE;
    idc->data->value->value.sequence = ASN1_STRING_new();
    idc->data->type = ctx->format->data_blob_get(&p, &l, ctx);
    idc->data->value->value.sequence->data = p;
    idc->data->value->value.sequence->length = l;
    idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(mdtype);
    idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
    idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

    hash = OPENSSL_zalloc((size_t)hashLen);
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
 * pkcs7_set_data_content()
 * [out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int appx_pkcs7_set_data_content(PKCS7 *p7, u_char *hash, int hashLen, FILE_FORMAT_CTX *ctx)
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
 * add_indirect_data_object()
 * [in, out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [returns] 0 on error or 1 on success
 */
static int appx_add_indirect_data_object(PKCS7 *p7, u_char *hash, int hashLen, FILE_FORMAT_CTX *ctx)
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


/*
 * APPX helper functions
 */

static u_char *appx_hash_blob_get(FILE_FORMAT_CTX *ctx, int *plen)
{
    int mdlen = EVP_MD_size(ctx->appx_ctx->md);
    int dataSize = ctx->appx_ctx->calculatedCIHash ? 4 + 5 * (mdlen + 4) : 4 + 4 * (mdlen + 4);
    u_char *data = OPENSSL_malloc((size_t)dataSize);
    int pos = 0;

    memcpy(data + pos, APPX_SIGNATURE, 4);
    pos += 4;
    memcpy(data + pos, AXPC_SIGNATURE, 4);
    pos += 4;
    memcpy(data + pos, ctx->appx_ctx->calculatedDataHash, (size_t)mdlen);
    pos += mdlen;
    memcpy(data + pos, AXCD_SIGNATURE, 4);
    pos += 4;
    memcpy(data + pos, ctx->appx_ctx->calculatedCDHash, (size_t)mdlen);
    pos += mdlen;
    memcpy(data + pos, AXCT_SIGNATURE, 4);
    pos += 4;
    memcpy(data + pos, ctx->appx_ctx->calculatedCTHash, (size_t)mdlen);
    pos += mdlen;
    memcpy(data + pos, AXBM_SIGNATURE, 4);
    pos += 4;
    memcpy(data + pos, ctx->appx_ctx->calculatedBMHash, (size_t)mdlen);
    pos += mdlen;
    if (ctx->appx_ctx->calculatedCIHash) {
        memcpy(data + pos, AXCI_SIGNATURE, 4);
        pos += 4;
        memcpy(data + pos, ctx->appx_ctx->calculatedCIHash, (size_t)mdlen);
        pos += mdlen;
    }
    *plen = pos;
    return data;
}

/*
 * Calculate hashes.
 * [in, out] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int appx_calculate_hashes(FILE_FORMAT_CTX *ctx)
{
    uint64_t cdOffset = 0;

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

    ctx->appx_ctx->calculatedBMHash = zipCalcDigest(ctx->appx_ctx->zip, BLOCK_MAP_FILENAME, ctx->appx_ctx->md);
    ctx->appx_ctx->calculatedCTHash = zipCalcDigest(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME, ctx->appx_ctx->md);
    ctx->appx_ctx->calculatedDataHash = appx_calc_zip_data_hash(ctx->appx_ctx->zip, ctx->appx_ctx->md, &cdOffset);
    ctx->appx_ctx->calculatedCDHash = appx_calc_zip_central_directory_hash(ctx->appx_ctx->zip, ctx->appx_ctx->md, cdOffset);
    ctx->appx_ctx->calculatedCIHash = zipCalcDigest(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME, ctx->appx_ctx->md);

    if (!ctx->appx_ctx->calculatedBMHash || !ctx->appx_ctx->calculatedCTHash
        || !ctx->appx_ctx->calculatedCDHash || !ctx->appx_ctx->calculatedDataHash) {
        printf("One or more hashes calculation failed\n");
        return 0; /* FAILED */
    }
    if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->calculatedCIHash) {
        printf("Code integrity file exists, but CI hash calculation failed\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

static uint8_t *appx_calc_zip_central_directory_hash(ZIP_FILE *zip, const EVP_MD *md, uint64_t cdOffset)
{
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());

    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    appx_write_central_directory(zip, bhash, 1, cdOffset);
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    return mdbuf;
}

/*
 * [returns] none
 */
static void appx_write_central_directory(ZIP_FILE *zip, BIO *bio, int removeSignature, uint64_t cdOffset)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    uint64_t offsetDiff = 0;
    uint64_t cdSize = 0;
    uint16_t noEntries = 0;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        /* the signature file is considered non existent for hashing purposes */
        uint64_t sizeOnDisk = 0;
        if (removeSignature && !strcmp(entry->fileName, APP_SIGNATURE_FILENAME)) {
            continue;
        }
        /* APP_SIGNATURE is nt 'tainted' by offset shift after replacing the contents of [content_types] */
        zipWriteCentralDirectoryEntry(bio, entry, strcmp(entry->fileName, APP_SIGNATURE_FILENAME) ? offsetDiff : 0, &sizeOnDisk);
        cdSize += sizeOnDisk;
        if (entry->overrideData) {
            offsetDiff += entry->overrideData->compressedSize - entry->compressedSize;
        }
        noEntries++;
    }
    if (zip->isZip64) {
        /* eocdr */
        BIO_write(bio, PKZIP64_EOCDR_SIGNATURE, 4);
        bioAddU64(bio, zip->eocdr64.eocdrSize);
        bioAddU16(bio, zip->eocdr64.creatorVersion);
        bioAddU16(bio, zip->eocdr64.viewerVersion);
        bioAddU32(bio, zip->eocdr64.diskNumber);
        bioAddU32(bio, zip->eocdr64.diskWithCentralDirectory);
        bioAddU64(bio, (uint64_t)noEntries);
        bioAddU64(bio, (uint64_t)noEntries);
        bioAddU64(bio, cdSize);
        bioAddU64(bio, cdOffset);

        if (zip->eocdr64.commentLen > 0) {
            size_t check;
            if (!BIO_write_ex(bio, zip->eocdr64.comment, zip->eocdr64.commentLen, &check)
                || check != zip->eocdr64.commentLen) {
                return; /* FAILED */
            }
        }
        /* eocdr locator */
        BIO_write(bio, PKZIP64_EOCD_LOCATOR_SIGNATURE, 4);
        bioAddU32(bio, zip->locator.diskWithEOCD);
        bioAddU64(bio, cdOffset + cdSize);
        bioAddU32(bio, zip->locator.totalNumberOfDisks);
    }

    BIO_write(bio, PKZIP_EOCDR_SIGNATURE, 4);
    /* those need to be 0s even though packaging tool writes FFFFs here
     * it will fail verification if not zeros */
    bioAddU16(bio, 0);
    bioAddU16(bio, 0);

    if (zip->eocdr.diskEntries != UINT16_MAX) {
        bioAddU16(bio, noEntries);
    } else {
        bioAddU16(bio, UINT16_MAX);
    }
    if (zip->eocdr.totalEntries != UINT16_MAX) {
        bioAddU16(bio, noEntries);
    } else {
        bioAddU16(bio, UINT16_MAX);
    }
    if (zip->eocdr.centralDirectorySize != UINT32_MAX) {
        bioAddU32(bio, (uint32_t)cdSize);
    } else {
        bioAddU32(bio, UINT32_MAX);
    }
    if (zip->eocdr.centralDirectoryOffset != UINT32_MAX) {
        bioAddU32(bio, (uint32_t)cdOffset);
    } else {
        bioAddU32(bio, UINT32_MAX);
    }
    bioAddU16(bio, zip->eocdr.commentLen);
    if (zip->eocdr.commentLen > 0) {
        BIO_write(bio, zip->eocdr.comment, zip->eocdr.commentLen);
    }
}

static uint8_t *appx_calc_zip_data_hash(ZIP_FILE *zip, const EVP_MD *md, uint64_t *cdOffset)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());

    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    *cdOffset = 0;
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        /* the signature file is considered not existent for hashing purposes */
        uint64_t sizeOnDisk = 0;
        if (!strcmp(entry->fileName, APP_SIGNATURE_FILENAME)) {
            continue;
        }
        if (!zipRewriteData(zip, entry, bhash, &sizeOnDisk)) {
            printf("Rewrite data error\n");
            return NULL; /* FAILED */
        }
        *cdOffset += sizeOnDisk;
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    return mdbuf;
}

/*
 * Extract hashes from SpcIndirectDataContent.
 * [in, out] ctx: structure holds input and output data
 * [out] content: SpcIndirectDataContent
 * [returns] 0 on error or 1 on success
 */
static int appx_extract_hashes(FILE_FORMAT_CTX *ctx, SpcIndirectDataContent *content)
{
#if 0
    AppxSpcSipInfo *si = NULL;
    uint8_t *blob = content->data->value->value.sequence->data;
    d2i_AppxSpcSipInfo(&si, &blob, content->data->value->value.sequence->length);
    long a = ASN1_INTEGER_get(si->a);
    long b = ASN1_INTEGER_get(si->b);
    long c = ASN1_INTEGER_get(si->c);
    long d = ASN1_INTEGER_get(si->d);
    long e = ASN1_INTEGER_get(si->e);
    long f = ASN1_INTEGER_get(si->f);
    BIO *stdbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    printf("a: 0x%x b: 0x%x c: 0x%x d: 0x%x e: 0x%x f: 0x%x\n", a, b, c, d, e, f);
    ASN1_STRING_print_ex(stdbio, si->string, ASN1_STRFLGS_RFC2253);
    AppxSpcSipInfo_free(si);
#endif
    int length = content->messageDigest->digest->length;
    uint8_t *data = content->messageDigest->digest->data;
    int mdlen = EVP_MD_size(ctx->appx_ctx->md);
    int pos = 4;

    /* we are expecting at least 4 hashes + 4 byte header */
    if (length < 4 * mdlen + 4) {
        printf("Hash too short\n");
        return 0; /* FAILED */
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

    if (memcmp(data, APPX_SIGNATURE, 4)) {
        printf("Hash signature does not match\n");
        return 0; /* FAILED */
    }

    while (pos + mdlen + 4 <= length) {
        if (!memcmp(data + pos, AXPC_SIGNATURE, 4)) {
            ctx->appx_ctx->existingDataHash = OPENSSL_malloc((size_t)mdlen);
            memcpy(ctx->appx_ctx->existingDataHash, data + pos + 4, (size_t)mdlen);
        } else if (!memcmp(data + pos, AXCD_SIGNATURE, 4)) {
            ctx->appx_ctx->existingCDHash = OPENSSL_malloc((size_t)mdlen);
            memcpy(ctx->appx_ctx->existingCDHash, data + pos + 4, (size_t)mdlen);
        } else if (!memcmp(data + pos, AXCT_SIGNATURE, 4)) {
            ctx->appx_ctx->existingCTHash = OPENSSL_malloc((size_t)mdlen);
            memcpy(ctx->appx_ctx->existingCTHash, data + pos + 4, (size_t)mdlen);
        } else if (!memcmp(data + pos, AXBM_SIGNATURE, 4)) {
            ctx->appx_ctx->existingBMHash = OPENSSL_malloc((size_t)mdlen);
            memcpy(ctx->appx_ctx->existingBMHash, data + pos + 4, (size_t)mdlen);
        } else if (!memcmp(data + pos, AXCI_SIGNATURE, 4)) {
            ctx->appx_ctx->existingCIHash = OPENSSL_malloc((size_t)mdlen);
            memcpy(ctx->appx_ctx->existingCIHash, data + pos + 4, (size_t)mdlen);
        } else {
            printf("Invalid hash signature\n");
            return 0; /* FAILED */
        }
        pos += mdlen + 4;
    }
    if (!ctx->appx_ctx->existingDataHash) {
        printf("File hash missing\n");
        return 0; /* FAILED */
    }
    if (!ctx->appx_ctx->existingCDHash) {
        printf("Central directory hash missing\n");
        return 0; /* FAILED */
    }
    if (!ctx->appx_ctx->existingBMHash) {
        printf("Block map hash missing\n");
        return 0; /* FAILED */
    }
    if (!ctx->appx_ctx->existingCTHash) {
        printf("Content types hash missing\n");
        return 0; /* FAILED */
    }
    if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->existingCIHash) {
        printf("Code integrity hash missing\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Compare hashes.
 * [in, out] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int appx_compare_hashes(FILE_FORMAT_CTX *ctx)
{
    int mdtype = EVP_MD_nid(ctx->appx_ctx->md);

    if (ctx->appx_ctx->calculatedBMHash && ctx->appx_ctx->existingBMHash) {
        printf("Checking Block Map hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingBMHash, ctx->appx_ctx->calculatedBMHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        printf("Block map hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedCTHash && ctx->appx_ctx->existingCTHash) {
        printf("Checking Content Types hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingCTHash, ctx->appx_ctx->calculatedCTHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        printf("Content Types hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedDataHash && ctx->appx_ctx->existingDataHash) {
        printf("Checking Data hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingDataHash, ctx->appx_ctx->calculatedDataHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        printf("Central Directory hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedCDHash && ctx->appx_ctx->existingCDHash) {
        printf("Checking Central Directory hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingCDHash, ctx->appx_ctx->calculatedCDHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        printf("Central Directory hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedCIHash && ctx->appx_ctx->existingCIHash) {
        printf("Checking Code Integrity hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingCIHash, ctx->appx_ctx->calculatedCIHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else if (!ctx->appx_ctx->calculatedCIHash && !ctx->appx_ctx->existingCIHash) {
        /* this is fine, CI file is optional -> if it is missing we expect both hashes to be non existent */
    } else {
        printf("Code Integrity hash missing\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * [returns] 0 on error or 1 on success
 */
static int appx_remove_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry)
{
    uint8_t *data;
    const char *cpos;
    size_t dataSize, ipos, len;
    int ret;

    if (!zipReadFileData(zip, entry, &data, (uint64_t *)&dataSize, 1)) {
        return 0; /* FAILED */
    }
    cpos = strstr((const char *)data, SIGNATURE_CONTENT_TYPES_ENTRY);
    if (!cpos) {
        printf("Did not find existing signature entry in %s\n", entry->fileName);
        OPENSSL_free(data);
        return 1; /* do not treat as en error */
    }
    /* *cpos > *data */
    ipos = (size_t)(cpos - (char *)data);
    len = strlen(SIGNATURE_CONTENT_TYPES_ENTRY);
    memmove(data + ipos, data + ipos + len, dataSize - ipos - len);
    dataSize -= len;
    ret = zipOverrideFileData(entry, data, (uint64_t)dataSize, 1);
    OPENSSL_free(data);
    return ret;
}

/*
 * [returns] 0 on error or 1 on success
 */
static int appx_append_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry)
{
    uint8_t *data, *newData;
    const char *existingEntry, *cpos;
    size_t dataSize, newSize, ipos, len;
    int ret;

    if (!zipReadFileData(zip, entry, &data, (uint64_t *)&dataSize, 1)) {
        return 0; /* FAILED */
    }
    existingEntry = strstr((const char *)data, SIGNATURE_CONTENT_TYPES_ENTRY);
    if (existingEntry) {
        OPENSSL_free(data);
        return 1; /* do not append it twice */
    }
    cpos = strstr((const char *)data, SIGNATURE_CONTENT_TYPES_CLOSING_TAG);
    if (!cpos) {
        printf("%s parsing error\n", entry->fileName);
        OPENSSL_free(data);
        return 0; /* FAILED */
    }
    ipos = (size_t)(cpos - (char *)data);
    len = strlen(SIGNATURE_CONTENT_TYPES_ENTRY);
    newSize = dataSize + len;
    newData = OPENSSL_malloc(newSize);
    memcpy(newData, data, ipos);
    memcpy(newData + ipos, SIGNATURE_CONTENT_TYPES_ENTRY, len);
    memcpy(newData + ipos + len, data + ipos, dataSize - ipos);
    ret = zipOverrideFileData(entry, newData, (uint64_t)newSize, 1);
    OPENSSL_free(data);
    OPENSSL_free(newData);
    return ret;
}

static const EVP_MD *appx_get_md(ZIP_FILE *zip)
{
    uint8_t *data = NULL;
    uint64_t dataSize = 0;
    char *start, *end, *pos;
    char *valueStart = NULL, *valueEnd = NULL;
    const EVP_MD *md = NULL;
    size_t slen;

    if (!zipReadFileDataByName(zip, BLOCK_MAP_FILENAME, &data, &dataSize, 1)) {
        printf("Could not read: %s\n", BLOCK_MAP_FILENAME);
        return NULL; /* FAILED */
    }
    start = strstr((const char *)data, HASH_METHOD_TAG);
    if (!start) {
        printf("Parse error: tag: %s not found in %s\n", HASH_METHOD_TAG, BLOCK_MAP_FILENAME);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    start += strlen(HASH_METHOD_TAG);
    if ((uint8_t *)start >= data + dataSize) {
        printf("Parse error: data too short in %s\n", BLOCK_MAP_FILENAME);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    end = strstr((const char *)start, ">");
    if (!end) {
        printf("Parse error: end of tag not found in %s\n", BLOCK_MAP_FILENAME);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    for (pos = start; pos != end; pos++) {
        if (*pos == '"') {
            if (!valueStart) {
                valueStart = pos + 1;
            } else {
                valueEnd = pos - 1;
            }
        }
    }
    if (!valueStart || !valueEnd || valueEnd <= valueStart) {
        printf("Parse error: value parse error in %s\n", BLOCK_MAP_FILENAME);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    slen = (size_t)(valueEnd - valueStart + 1);
    if (strlen(HASH_METHOD_SHA256) == slen && !memcmp(valueStart, HASH_METHOD_SHA256, slen)) {
        printf("Hash method is SHA256\n");
        md = EVP_sha256();
    } else if (strlen(HASH_METHOD_SHA384) == slen && !memcmp(valueStart, HASH_METHOD_SHA384, slen)) {
        printf("Hash method is SHA384\n");
        md = EVP_sha384();
    } else if (strlen(HASH_METHOD_SHA512) == slen && !memcmp(valueStart, HASH_METHOD_SHA512, slen)) {
        printf("Hash method is SHA512\n");
        md = EVP_sha512();
    }
    OPENSSL_free(data);
    return md;
}

static ZIP_CENTRAL_DIRECTORY_ENTRY *zipGetCDEntryByName(ZIP_FILE *zip, const char *name)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (!strcmp(entry->fileName, name)) {
            return entry;
        }
    }
    return NULL; /* FAILED */
}

/*
 * [returns] none
 */
static void zipWriteCentralDirectoryEntry(BIO *bio, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint64_t offsetDiff, uint64_t *sizeOnDisk)
{
    uint16_t zip64ChunkSize = 0;

    BIO_write(bio, PKZIP_CD_SIGNATURE, 4);
    bioAddU16(bio, entry->creatorVersion);
    bioAddU16(bio, entry->viewerVersion);
    bioAddU16(bio, entry->flags);
    bioAddU16(bio, entry->compression);
    bioAddU16(bio, entry->modTime);
    bioAddU16(bio, entry->modDate);
    bioAddU32(bio, entry->overrideData ? entry->overrideData->crc32 : entry->crc32);
    bioAddU32(bio, entry->compressedSizeInZip64 ? UINT32_MAX : entry->overrideData ? (uint32_t)entry->overrideData->compressedSize : (uint32_t)entry->compressedSize);
    bioAddU32(bio, entry->uncompressedSizeInZip64 ? UINT32_MAX : entry->overrideData ? (uint32_t)entry->overrideData->uncompressedSize : (uint32_t)entry->uncompressedSize);
    bioAddU16(bio, entry->fileNameLen);
    bioAddU16(bio, entry->extraFieldLen);
    bioAddU16(bio, entry->fileCommentLen);
    bioAddU16(bio, entry->diskNoInZip64 ? UINT16_MAX : (uint16_t)entry->diskNoStart);
    bioAddU16(bio, entry->internalAttr);
    bioAddU32(bio, entry->externalAttr);
    bioAddU32(bio, entry->offsetInZip64 ? UINT32_MAX : (uint32_t)(entry->offsetOfLocalHeader + offsetDiff));

    if (entry->fileNameLen > 0 && entry->fileName) {
        BIO_write(bio, entry->fileName, entry->fileNameLen);
    }
    if (entry->uncompressedSizeInZip64) {
        zip64ChunkSize += 8;
    }
    if (entry->compressedSizeInZip64) {
        zip64ChunkSize += 8;
    }
    if (entry->offsetInZip64) {
        zip64ChunkSize += 8;
    }
    if (entry->diskNoInZip64) {
        zip64ChunkSize += 4;
    }
    if (zip64ChunkSize > 0) {
        bioAddU16(bio, ZIP64_HEADER);
        bioAddU16(bio, zip64ChunkSize);
        if (entry->uncompressedSizeInZip64) {
            bioAddU64(bio, entry->overrideData ? entry->overrideData->uncompressedSize : entry->uncompressedSize);
        }
        if (entry->compressedSizeInZip64) {
            bioAddU64(bio, entry->overrideData ? entry->overrideData->compressedSize : entry->compressedSize);
        }
        if (entry->offsetInZip64) {
            bioAddU64(bio, entry->offsetOfLocalHeader + offsetDiff);
        }
        if (entry->diskNoInZip64) {
            bioAddU32(bio, entry->diskNoStart);
        }
    }
#if 0
    if (entry->extraFieldLen > 0 && entry->extraField)
    {
        /* todo, if override daata, need to rewrite the extra field */
        BIO_write(bio, entry->extraField, entry->extraFieldLen);
    }
#endif
    if (entry->fileCommentLen > 0 && entry->fileComment) {
        BIO_write(bio, entry->fileComment, entry->fileCommentLen);
    }
    *sizeOnDisk = (uint64_t)46 + entry->fileNameLen + entry->extraFieldLen + entry->fileCommentLen;
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipAppendFile(ZIP_FILE *zip, BIO *bio, const char *fn, uint8_t *data, uint64_t dataSize, int comprs)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    ZIP_LOCAL_HEADER header;
    time_t tim;
    struct tm *timeinfo;
    uint32_t crc;
    uint64_t offset, dummy = 0, written = 0, sizeToWrite = dataSize;
    uint8_t *dataToWrite = data;

    memset(&header, 0, sizeof(ZIP_LOCAL_HEADER));
    if (comprs) {
        int ret;

        dataToWrite = OPENSSL_malloc(dataSize);
        uint64_t destLen = dataSize;
        ret = zipDeflate(dataToWrite, &destLen, data, dataSize, 8);
        if (ret != Z_OK) {
            printf("Zip deflate failed: %d\n", ret);
            OPENSSL_free(dataToWrite);
            return 0; /* FAILED */
        }
        sizeToWrite = destLen;
    }
    time(&tim);
    timeinfo = localtime(&tim);

    header.version = 0x14;
    header.flags = 0;
    header.compression = comprs ? COMPRESSION_DEFLATE : 0;
    header.modTime = (uint16_t)(timeinfo->tm_hour << 11 | \
                                timeinfo->tm_min << 5 | \
                                timeinfo->tm_sec >> 1);
    header.modDate = (uint16_t)((timeinfo->tm_year - 80) << 9 | \
                                (timeinfo->tm_mon + 1) << 5 | \
                                timeinfo->tm_mday);

    /* TODO */
    crc = (uint32_t)crc32(0L, Z_NULL, 0);
    crc = (uint32_t)crc32(crc, data, (uint32_t)dataSize);

    header.crc32 = crc;
    header.uncompressedSize = dataSize;
    header.compressedSize = sizeToWrite;
    header.fileNameLen = (uint16_t)strlen(fn);
    /* this will be reassigned to CD entry and freed there */
    header.fileName = OPENSSL_zalloc(header.fileNameLen + 1);
    memcpy(header.fileName, fn, header.fileNameLen);
    header.extraField = NULL;
    header.extraFieldLen = 0;

    /* unfortunately BIO has no 64bit API, so we are limited to 2G files...
     * should probably rewrite it with using stdio and ftello64 */
    offset = (uint64_t)BIO_tell(bio);

    zipWriteLocalHeader(bio, &header, &dummy);
    while (sizeToWrite > 0) {
        uint64_t toWrite = sizeToWrite < SIZE_64K ? sizeToWrite : SIZE_64K;
        size_t check;
        if (!BIO_write_ex(bio, dataToWrite + written, toWrite, &check)
            || check != toWrite) {
            return 0; /* FAILED */
        }
        sizeToWrite -= toWrite;
        written += toWrite;
    }
    if (comprs) {
        OPENSSL_free(dataToWrite);
    }
    entry = OPENSSL_zalloc(sizeof(ZIP_CENTRAL_DIRECTORY_ENTRY));
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

    if (!zip->centralDirectoryHead) {
        zip->centralDirectoryHead = entry;
    } else {
        ZIP_CENTRAL_DIRECTORY_ENTRY *last = zip->centralDirectoryHead;
        while (last->next) {
            last = last->next;
        }
        last->next = entry;
    }
    return 1; /* OK */
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipOverrideFileData(ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint8_t *data, uint64_t dataSize, int comprs)
{
    uint32_t crc;

    if (entry->overrideData) {
        OPENSSL_free(entry->overrideData->data);
        OPENSSL_free(entry->overrideData);
        entry->overrideData = NULL;
    }
    entry->overrideData = OPENSSL_malloc(sizeof(ZIP_OVERRIDE_DATA));
    entry->overrideData->data = OPENSSL_malloc(dataSize);

    /* TODO */
    crc = (uint32_t)crc32(0L, Z_NULL, 0);
    crc = (uint32_t)crc32(crc, data, (uint32_t)dataSize);
    entry->overrideData->crc32 = crc;
    entry->overrideData->uncompressedSize = dataSize;

    if (comprs) {
        uint64_t destLen = dataSize;
        int ret = zipDeflate(entry->overrideData->data, &destLen, data, dataSize, 8);
        if (ret != Z_OK) {
            printf("Zip deflate failed: %d\n", ret);
            return 0; /* FAILED */
        }
        entry->overrideData->compressedSize = destLen;
    } else {
        memcpy(entry->overrideData, data, dataSize);
        entry->overrideData->compressedSize = dataSize;
    }
    return 1; /* OK */
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipRewriteData(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, BIO *bio, uint64_t *sizeOnDisk)
{
    size_t check;
    ZIP_LOCAL_HEADER header;

    memset(&header, 0, sizeof(header));
    if (fseeko(zip->file, (int64_t)entry->offsetOfLocalHeader, SEEK_SET) < 0) {
        return 0; /* FAILED */
    }
    if (!zipReadLocalHeader(&header, zip, entry->compressedSize)) {
        return 0; /* FAILED */
    }
    if (entry->overrideData) {
        header.compressedSize = entry->overrideData->compressedSize;
        header.uncompressedSize = entry->overrideData->uncompressedSize;
        header.crc32 = entry->overrideData->crc32;
    }
    zipWriteLocalHeader(bio, &header, sizeOnDisk);
    if (entry->overrideData) {
        if (!BIO_write_ex(bio, entry->overrideData->data, entry->overrideData->compressedSize, &check)
            || check != entry->overrideData->compressedSize) {
            return 0; /* FAILED */
        }
        if (fseeko(zip->file, (int64_t)entry->compressedSize, SEEK_CUR) < 0) {
            return 0; /* FAILED */
        }
        *sizeOnDisk += entry->overrideData->compressedSize;
    } else {
        uint64_t len = entry->compressedSize;
        uint8_t *data = OPENSSL_malloc(SIZE_64K);
        while (len > 0) {
            uint64_t toWrite = len < SIZE_64K ? len : SIZE_64K;
            size_t size = fread(data, 1, toWrite, zip->file);
            if (size != toWrite) {
                OPENSSL_free(data);
                return 0; /* FAILED */
            }
            if (!BIO_write_ex(bio, data, toWrite, &check)
                || check != toWrite) {
                OPENSSL_free(data);
                return 0; /* FAILED */
            }
            *sizeOnDisk += toWrite;
            len -= toWrite;
        }
        OPENSSL_free(data);
    }
    if (header.flags & DATA_DESCRIPTOR_BIT) {
        BIO_write(bio, PKZIP_DATA_DESCRIPTOR_SIGNATURE, 4);
        bioAddU32(bio, header.crc32);
        if (zip->isZip64) {
            bioAddU64(bio, header.compressedSize);
            bioAddU64(bio, header.uncompressedSize);
        } else {
            bioAddU32(bio, (uint32_t)header.compressedSize);
            bioAddU32(bio, (uint32_t)header.uncompressedSize);
        }
        if (zip->isZip64) {
            if (fseeko(zip->file, 24, SEEK_CUR) < 0) {
                return 0; /* FAILED */
            }
            *sizeOnDisk += 24;
        } else {
            if (fseeko(zip->file, 16, SEEK_CUR) < 0) {
                return 0; /* FAILED */
            }
            *sizeOnDisk += 16;
        }
    }
    OPENSSL_free(header.fileName);
    OPENSSL_free(header.extraField);
    return 1; /* OK */
}

/*
 * [returns] none
 */
static void zipWriteLocalHeader(BIO *bio, ZIP_LOCAL_HEADER *header, uint64_t *sizeonDisk)
{
    BIO_write(bio, PKZIP_LH_SIGNATURE, 4);
    bioAddU16(bio, header->version);
    bioAddU16(bio, header->flags);
    bioAddU16(bio, header->compression);
    bioAddU16(bio, header->modTime);
    bioAddU16(bio, header->modDate);

    if (header->flags & DATA_DESCRIPTOR_BIT) {
        bioAddU32(bio, 0);
        bioAddU32(bio, 0);
        bioAddU32(bio, 0);
    } else {
        bioAddU32(bio, header->crc32);
        bioAddU32(bio, header->compressedSizeInZip64 ? UINT32_MAX : (uint32_t)header->compressedSize);
        bioAddU32(bio, header->uncompressedSizeInZip64 ? UINT32_MAX : (uint32_t)header->uncompressedSize);
    }
    bioAddU16(bio, header->fileNameLen);
    bioAddU16(bio, header->extraFieldLen);

    if (header->fileNameLen > 0) {
        BIO_write(bio, header->fileName, header->fileNameLen);
    }
    if (header->extraFieldLen > 0) {
        BIO_write(bio, header->extraField, header->extraFieldLen);
    }
    *sizeonDisk = (uint64_t)30 + header->fileNameLen + header->extraFieldLen;
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipEntryExist(ZIP_FILE *zip, const char *name)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (!strcmp(name, entry->fileName)) {
            return 1; /* OK */
        }
    }
    return 0; /* FAILED */
}

static u_char *zipCalcDigest(ZIP_FILE *zip, const char *fileName, const EVP_MD *md)
{
    uint8_t *data = NULL;
    uint64_t dataSize = 0;
    u_char *mdbuf = NULL;
    BIO *bhash;

    if (!zipReadFileDataByName(zip, fileName, &data, &dataSize, 1)) {
        return NULL; /* FAILED */
    }
    bhash = BIO_new(BIO_f_md());
    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        OPENSSL_free(data);
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    if (!bio_hash_data(bhash, (char *)data, 0, dataSize)) {
        OPENSSL_free(data);
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
    OPENSSL_free(data);
    BIO_free_all(bhash);

    return mdbuf;
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipReadFileDataByName(ZIP_FILE *zip, const char *name, uint8_t **pData, uint64_t *dataSize, int unpack)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (!strcmp(name, entry->fileName)) {
            return zipReadFileData(zip, entry, pData, dataSize, unpack);
        }
    }
    return 0; /* FAILED */
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipReadFileData(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint8_t **pData, uint64_t *dataSize, int unpack)
{
    FILE *file = zip->file;
    uint8_t *compressedData = NULL;
    uint64_t compressedSize = 0;
    uint64_t uncompressedSize = 0;
    size_t size;

    if (fseeko(file, (int64_t)entry->offsetOfLocalHeader, SEEK_SET) < 0) {
        return 0; /* FAILED */
    }
    if (entry->overrideData) {
        compressedSize = entry->overrideData->compressedSize;
        uncompressedSize = entry->overrideData->uncompressedSize;
        compressedData = OPENSSL_zalloc(compressedSize + 1);
        memcpy(compressedData, entry->overrideData->data, compressedSize);
    } else {
        ZIP_LOCAL_HEADER header;
        compressedSize = entry->compressedSize;
        uncompressedSize = entry->uncompressedSize;
        memset(&header, 0, sizeof(header));
        if (!zipReadLocalHeader(&header, zip, compressedSize)) {
            return 0; /* FAILED */
        }
        if (header.fileNameLen != entry->fileNameLen
            || memcmp(header.fileName, entry->fileName, header.fileNameLen)
            || header.compressedSize != compressedSize
            || header.uncompressedSize != uncompressedSize
            || header.compression != entry->compression) {
            printf("Local header does not match central directory entry\n");
            return 0; /* FAILED */
        }
        /* we don't really need those */
        OPENSSL_free(header.fileName);
        OPENSSL_free(header.extraField);

        compressedData = OPENSSL_zalloc(compressedSize + 1);
        size = fread(compressedData, 1, compressedSize, file);
        if (size != compressedSize) {
            OPENSSL_free(compressedData);
            return 0; /* FAILED */
        }
    }
    if (!unpack || (unpack && entry->compression == COMPRESSION_NONE)) {
        *pData = compressedData;
        *dataSize = compressedSize;
    } else if (entry->compression == COMPRESSION_DEFLATE) {
        uint8_t *uncompressedData = OPENSSL_zalloc(uncompressedSize + 1);
        uint64_t destLen = uncompressedSize;
        uint64_t sourceLen = compressedSize;
        int ret;

        ret = zipInflate(uncompressedData, &destLen, compressedData, &sourceLen);
        OPENSSL_free(compressedData);

        if (ret != Z_OK) {
            printf("Data decompresssion failed, zlib error: %d\n", ret);
            OPENSSL_free(uncompressedData);
            return 0; /* FAILED */
        } else {
            *pData = uncompressedData;
            *dataSize = destLen;
        }
    } else {
        printf("Unsupported compression mode: %d\n", entry->compression);
        OPENSSL_free(compressedData);
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Read local file header
 * [returns] 0 on error or 1 on success
 */
static int zipReadLocalHeader(ZIP_LOCAL_HEADER *header, ZIP_FILE *zip, uint64_t compressedSize)
{
    char signature[4];
    size_t size;
    FILE *file = zip->file;

    size = fread(signature, 1, 4, file);
    if (size != 4) {
        return 0; /* FAILED */
    }
    if (memcmp(signature, PKZIP_LH_SIGNATURE, 4)) {
        printf("The input file is not a valip zip file - local header signature does not match\n");
        return 0; /* FAILED */
    }
    /* version needed to extract (2 bytes) */
    header->version = fileGetU16(file);
    /* general purpose bit flag (2 bytes) */
    header->flags = fileGetU16(file);
    /* compression method (2 bytes) */
    header->compression = fileGetU16(file);
    /* last mod file time (2 bytes) */
    header->modTime = fileGetU16(file);
    /* last mod file date (2 bytes) */
    header->modDate = fileGetU16(file);
    /* crc-32 (4 bytes) */
    header->crc32 = fileGetU32(file);
    /* compressed size (4 bytes) */
    header->compressedSize = fileGetU32(file);
    /* uncompressed size (4 bytes) */
    header->uncompressedSize = fileGetU32(file);
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    /* file name length (2 bytes) */
    header->fileNameLen = fileGetU16(file);
    if (header->fileNameLen > UINT16_MAX) {
        printf("Corrupted file name length : 0x%08X\n", header->fileNameLen);
        return 0; /* FAILED */
    }
    /* extra file name length (2 bytes) */
    header->extraFieldLen = fileGetU16(file);
    if (header->extraFieldLen > UINT16_MAX) {
        printf("Corrupted extra file name length : 0x%08X\n", header->extraFieldLen);
        return 0; /* FAILED */
    }
    #pragma GCC diagnostic pop
    /* file name (variable size) */
    if (header->fileNameLen > 0) {
        header->fileName = OPENSSL_zalloc(header->fileNameLen + 1);
        size = fread(header->fileName, 1, header->fileNameLen, file);
        if (size != header->fileNameLen) {
            return 0; /* FAILED */
        }
    } else {
        header->fileName = NULL;
    }
    /* extra field (variable size) */
    if (header->extraFieldLen > 0) {
        header->extraField = OPENSSL_zalloc(header->extraFieldLen);
        size = fread(header->extraField, 1, header->extraFieldLen, file);
        if (size != header->extraFieldLen) {
            return 0; /* FAILED */
        }
    } else {
        header->extraField = NULL;
    }
    if (header->flags & DATA_DESCRIPTOR_BIT) {
        /* Read data descriptor */
        int64_t offset = ftello(file);
        if (offset < 0) {
           return 0; /* FAILED */
        }
        if (fseeko(file, (int64_t)compressedSize, SEEK_CUR) < 0) {
            return 0; /* FAILED */
        }
        size = fread(signature, 1, 4, file);
        if (size != 4) {
            return 0; /* FAILED */
        }
        if (memcmp(signature, PKZIP_DATA_DESCRIPTOR_SIGNATURE, 4)) {
            printf("The input file is not a valip zip file - flags indicate data descriptor, but data descriptor signature does not match\n");
            OPENSSL_free(header->fileName);
            OPENSSL_free(header->extraField);
            return 0; /* FAILED */
        }
        header->crc32 = fileGetU32(file);
        if (zip->isZip64) {
            header->compressedSize = fileGetU64(file);
            header->uncompressedSize = fileGetU64(file);
        } else {
            header->compressedSize = fileGetU32(file);
            header->uncompressedSize = fileGetU32(file);
        }
        if (fseeko(file, offset, SEEK_SET) < 0) {
            return 0; /* FAILED */
        }
    }
    if (header->uncompressedSize == UINT32_MAX || header->compressedSize == UINT32_MAX) {
        if (header->extraFieldLen > 4) {
            uint64_t pos = 0;
            uint16_t len;
            uint16_t op = bufferGetU16(header->extraField, &pos);

            if (op != ZIP64_HEADER) {
                printf("Expected zip64 header in local header extra field, got : 0x%X\n", op);
                OPENSSL_free(header->fileName);
                OPENSSL_free(header->extraField);
                header->fileName = NULL;
                header->extraField = NULL;
                return 0; /* FAILED */
            }
            len = bufferGetU16(header->extraField, &pos);
            if (header->uncompressedSize == UINT32_MAX) {
                if (len >= 8) {
                    header->uncompressedSize = bufferGetU64(header->extraField, &pos);
                    header->uncompressedSizeInZip64 = 1;
                } else {
                    printf("Invalid zip64 local header entry\n");
                    OPENSSL_free(header->fileName);
                    OPENSSL_free(header->extraField);
                    header->fileName = NULL;
                    header->extraField = NULL;
                    return 0; /* FAILED */
                }
            }
            if (header->compressedSize == UINT32_MAX) {
                if (len >= 16) {
                    header->compressedSize = bufferGetU64(header->extraField, &pos);
                    header->compressedSizeInZip64 = 1;
                } else {
                    printf("Invalid zip64 local header entry\n");
                    OPENSSL_free(header->fileName);
                    OPENSSL_free(header->extraField);
                    header->fileName = NULL;
                    header->extraField = NULL;
                    return 0; /* FAILED */
                }
            }
        } else {
            OPENSSL_free(header->fileName);
            OPENSSL_free(header->extraField);
            header->fileName = NULL;
            header->extraField = NULL;
            return 0; /* FAILED */
        }
    }
    return 1; /* OK */
}

/*
 * Decompresses the source buffer into the destination buffer.
 * see: uncompress2()
 * https://github.com/madler/zlib/blob/09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851/uncompr.c#L27
 * [out] dest: destination buffer
 * [out] destLen: size of the decompressed data
 * [in] source: source buffer
 * [in] sourceLen: length of the source buffer
 * [returns] returns ZIP error or Z_OK if success
 */
static int zipInflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong *sourceLen)
{
    z_stream stream;
    int err;
    const uInt max = (uInt)-1;
    uLong len, left;
     /* for detection of incomplete stream when *destLen == 0 */
    static u_char buf[] = { 0x00 };

    len = *sourceLen;
    if (*destLen) {
        left = *destLen;
        *destLen = 0;
    } else {
        left = 1;
        dest = buf;
    }
    stream.next_in = source;
    stream.avail_in = 0;
    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;
    stream.opaque = (voidpf)0;
    err = inflateInit2(&stream, -MAX_WBITS);
    if (err != Z_OK) {
        return err;
    }
    stream.next_out = dest;
    stream.avail_out = 0;
    do {
        if (stream.avail_out == 0) {
            stream.avail_out = left > (uLong)max ? max : (uInt)left;
            left -= stream.avail_out;
        }
        if (stream.avail_in == 0) {
            stream.avail_in = len > (uLong)max ? max : (uInt)len;
            len -= stream.avail_in;
        }
        err = inflate(&stream, Z_NO_FLUSH);
    } while (err == Z_OK);
    *sourceLen -= len + stream.avail_in;

    if (dest != buf) {
        *destLen = stream.total_out;
    } else if (stream.total_out && err == Z_BUF_ERROR) {
        left = 1;
    }
    inflateEnd(&stream);

    return err == Z_STREAM_END ? Z_OK :
        err == Z_NEED_DICT ? Z_DATA_ERROR :
        err == Z_BUF_ERROR && left + stream.avail_out ? Z_DATA_ERROR :
        err;
}

/*
 * Compresses the source buffer into the destination buffer.
 * see: compress2()
 * https://github.com/madler/zlib/blob/09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851/compress.c#L22
 * [out] dest: destination buffer
 * [out] destLen: actual size of the compressed buffer
 * [in] source: source buffer
 * [in] sourceLen: length of the source buffer
 * [in] level: deflateInit2 parameter (8)
 * [returns] returns ZIP error or Z_OK if success
 */
static int zipDeflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong sourceLen, int level)
{
    z_stream stream;
    int err;
    const uInt max = (uInt)-1;
    uLong left;

    /* reset stream */
    memset(&stream, 0, sizeof stream);

    left = *destLen;
    *destLen = 0;
    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;
    stream.opaque = (voidpf)0;

    err = deflateInit2(&stream, level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    if (err != Z_OK) {
        return err;
    }
    stream.next_out = dest;
    stream.avail_out = 0;
    stream.next_in = source;
    stream.avail_in = 0;
    do {
        if (stream.avail_out == 0) {
            stream.avail_out = left > (uLong)max ? max : (uInt)left;
            left -= stream.avail_out;
        }
        if (stream.avail_in == 0) {
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

static ZIP_FILE *openZip(const char *fn)
{
    ZIP_FILE *zip;
    FILE *file = fopen(fn, "rb");

    if (!file) {
        return NULL; /* FAILED */
    }
    /* oncde we read eocdr, comment might be allocated and we need to take care of it -> create the zipFile structure */
    zip = OPENSSL_zalloc(sizeof(ZIP_FILE));
    zip->file = file;
    if (!readZipEOCDR(&zip->eocdr, file)) {
        freeZip(zip);
        return NULL; /* FAILED */
    }
    if (fseeko(file, 0, SEEK_END) < 0) {
        freeZip(zip);
        return NULL; /* FAILED */
    }
    zip->fileSize = ftello(file);
    if (zip->fileSize < 0) {
        freeZip(zip);
        return NULL; /* FAILED */
    }
    if (zip->eocdr.centralDirectoryOffset == UINT32_MAX || zip->eocdr.centralDirectorySize == UINT32_MAX) {
        /* probably a zip64 file */
        if (!readZip64EOCDLocator(&zip->locator, file)) {
            freeZip(zip);
            return NULL; /* FAILED */
        }
        if (!readZip64EOCDR(&zip->eocdr64, file, zip->locator.eocdOffset)) {
            freeZip(zip);
            return NULL; /* FAILED */
        }
        zip->isZip64 = 1;
        zip->eocdrOffset = zip->locator.eocdOffset;
        zip->eocdrLen = zip->fileSize - (int64_t)zip->eocdrOffset;
        if (zip->eocdrLen < 0) {
            freeZip(zip);
            return NULL; /* FAILED */
        }
        zip->centralDirectoryOffset = zip->eocdr64.centralDirectoryOffset;
        zip->centralDirectorySize = zip->eocdr64.centralDirectorySize;
        zip->centralDirectoryRecordCount = zip->eocdr64.totalEntries;
    } else {
        if (zip->fileSize < EOCDR_SIZE) {
            freeZip(zip);
            return NULL; /* FAILED */
        }
        zip->eocdrOffset = (uint64_t)zip->fileSize - EOCDR_SIZE;
        zip->eocdrLen = EOCDR_SIZE;
        zip->centralDirectoryOffset = zip->eocdr.centralDirectoryOffset;
        zip->centralDirectorySize = zip->eocdr.centralDirectorySize;
        zip->centralDirectoryRecordCount = zip->eocdr.totalEntries;
    }

    if (!zipReadCentralDirectory(zip, file)) {
        freeZip(zip);
        return NULL; /* FAILED */
    }

    return zip;
}

/*
 * Free up ZIP_FILE structure.
 * [in] ZIP_FILE structure
 * [returns] none
 */
static void freeZip(ZIP_FILE *zip)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

    fclose(zip->file);
    OPENSSL_free(zip->eocdr.comment);
    OPENSSL_free(zip->eocdr64.comment);
    ZIP_CENTRAL_DIRECTORY_ENTRY *next = NULL;
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = next) {
        next = entry->next;
        freeZipCentralDirectoryEntry(entry);
    }
    OPENSSL_free(zip);
}

/*
 * Log additional output.
 * [in] ZIP_FILE structure
 * [returns] none
 */
static void zipPrintCentralDirectory(ZIP_FILE *zip)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

    printf("Central directory entry count: %" PRIu64"\n", zip->centralDirectoryRecordCount);
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        printf("Name: %s Compressed: %" PRIu64" Uncompressed: %" PRIu64" Offset: %" PRIu64"\n", entry->fileName,
            entry->compressedSize, entry->uncompressedSize, entry->offsetOfLocalHeader);
    }
}

/*
 * [returns] 0 on error or 1 on success
 */
static int zipReadCentralDirectory(ZIP_FILE *zip, FILE *file)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *prev = NULL;
    uint64_t i;

    if (fseeko(file, (int64_t)zip->centralDirectoryOffset, SEEK_SET) < 0) {
        return 0; /* FAILED */
    }
    for (i = 0; i < zip->centralDirectoryRecordCount; i++) {
        ZIP_CENTRAL_DIRECTORY_ENTRY *entry = zipReadNextCentralDirectoryEntry(file);
        if (!entry) {
            return 0; /* FAILED */
        }
        if (prev) {
            prev->next = entry;
        } else if (!zip->centralDirectoryHead) {
            zip->centralDirectoryHead = entry;
        } else {
            printf("Corrupted central directory structure\n");
            return 0; /* FAILED */
        }
        prev = entry;
    }
    return 1; /* OK */
}

/*
 * Initialize central directory structure.
 * [in] file: FILE pointer
 * [returns] Central directory structure
 */
static ZIP_CENTRAL_DIRECTORY_ENTRY *zipReadNextCentralDirectoryEntry(FILE *file)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    char signature[4];
    size_t size = fread(signature, 1, 4, file);

    if (size != 4) {
        return NULL; /* FAILED */
    }
    if (memcmp(signature, PKZIP_CD_SIGNATURE, 4)) {
        printf("The input file is not a valip zip file - could not find Central Directory record\n");
        return NULL; /* FAILED */
    }
    entry = OPENSSL_zalloc(sizeof(ZIP_CENTRAL_DIRECTORY_ENTRY));
    entry->fileOffset = ftello(file) - 4;
    if (entry->fileOffset < 0) {
        freeZipCentralDirectoryEntry(entry);
        return NULL; /* FAILED */
    }
    /* version made by (2 bytes) */
    entry->creatorVersion = fileGetU16(file);
    /* version needed to extract (2 bytes) */
    entry->viewerVersion = fileGetU16(file);
    /* general purpose bit flag (2 bytes) */
    entry->flags = fileGetU16(file);
    /* compression method (2 bytes) */
    entry->compression = fileGetU16(file);
    /* last mod file time (2 bytes) */
    entry->modTime = fileGetU16(file);
    /* last mod file date (2 bytes) */
    entry->modDate = fileGetU16(file);
    /* crc-32 (4 bytes) */
    entry->crc32 = fileGetU32(file);
    /* compressed size (4 bytes) */
    entry->compressedSize = fileGetU32(file);
    /* uncompressed size (4 bytes) */
    entry->uncompressedSize = fileGetU32(file);
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    /* file name length (2 bytes) */
    entry->fileNameLen = fileGetU16(file);
    if (entry->fileNameLen > UINT16_MAX) {
        printf("Corrupted file name length : 0x%08X\n", entry->fileNameLen);
        freeZipCentralDirectoryEntry(entry);
        return NULL; /* FAILED */
    }
    /* extra field length (2 bytes) */
    entry->extraFieldLen = fileGetU16(file);
    if (entry->extraFieldLen > UINT16_MAX) {
        printf("Corrupted extra field length : 0x%08X\n", entry->extraFieldLen);
        freeZipCentralDirectoryEntry(entry);
        return NULL; /* FAILED */
    }
    /* file comment length (2 bytes) */
    entry->fileCommentLen = fileGetU16(file);
    if (entry->fileCommentLen > UINT16_MAX) {
        printf("Corrupted file comment length : 0x%08X\n", entry->fileCommentLen);
        freeZipCentralDirectoryEntry(entry);
        return NULL; /* FAILED */
    }
    #pragma GCC diagnostic pop
    /* disk number start (2 bytes) */
    entry->diskNoStart = fileGetU16(file);
    /* internal file attributes (2 bytes) */
    entry->internalAttr = fileGetU16(file);
    /* external file attributes (4 bytes) */
    entry->externalAttr = fileGetU32(file);
    /* relative offset of local header (4 bytes) */
    entry->offsetOfLocalHeader = fileGetU32(file);
    /* file name (variable size) */
    if (entry->fileNameLen > 0) {
        entry->fileName = OPENSSL_zalloc(entry->fileNameLen + 1);
        size = fread(entry->fileName, 1, entry->fileNameLen, file);
        if (size != entry->fileNameLen) {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
    }
    /* extra field (variable size) */
    if (entry->extraFieldLen > 0) {
        entry->extraField = OPENSSL_zalloc(entry->extraFieldLen);
        size = fread(entry->extraField, 1, entry->extraFieldLen, file);
        if (size != entry->extraFieldLen) {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
    }
    /* file comment (variable size) */
    if (entry->fileCommentLen > 0) {
        entry->fileComment = OPENSSL_zalloc(entry->fileCommentLen + 1);
        size = fread(entry->fileComment, 1, entry->fileCommentLen, file);
        if (size != entry->fileCommentLen) {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
    }
    if (entry->uncompressedSize == UINT32_MAX || entry->compressedSize == UINT32_MAX ||
        entry->offsetOfLocalHeader == UINT32_MAX || entry->diskNoStart == UINT16_MAX) {
        if (entry->extraFieldLen > 4) {
            uint64_t pos = 0;
            uint64_t len;
            uint16_t header = bufferGetU16(entry->extraField, &pos);

            if (header != ZIP64_HEADER) {
                printf("Expected zip64 header in central directory extra field, got : 0x%X\n", header);
                freeZipCentralDirectoryEntry(entry);
                return NULL; /* FAILED */
            }
            len = bufferGetU16(entry->extraField, &pos);
            if (entry->uncompressedSize == UINT32_MAX) {
                if (len >= 8) {
                    entry->uncompressedSize = bufferGetU64(entry->extraField, &pos);
                    entry->uncompressedSizeInZip64 = 1;
                } else {
                    printf("Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
            if (entry->compressedSize == UINT32_MAX) {
                if (len >= 16) {
                    entry->compressedSize = bufferGetU64(entry->extraField, &pos);
                    entry->compressedSizeInZip64 = 1;
                } else {
                    printf("Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
            if (entry->offsetOfLocalHeader == UINT32_MAX) {
                if (len >= 24) {
                    entry->offsetOfLocalHeader = bufferGetU64(entry->extraField, &pos);
                    entry->offsetInZip64 = 1;
                } else {
                    printf("Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
            if (entry->diskNoStart == UINT16_MAX) {
                if (len >= 28) {
                    entry->diskNoStart = bufferGetU32(entry->extraField, &pos);
                    entry->diskNoInZip64 = 1;
                } else {
                    printf("Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
        } else {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
    }
    entry->entryLen = ftello(file) - entry->fileOffset;
    if (entry->entryLen < 0) {
        freeZipCentralDirectoryEntry(entry);
        return NULL; /* FAILED */
    }
    return entry;
}

/*
 * Free up central directory structure.
 * [in] central directory structure
 * [returns] none
 */
static void freeZipCentralDirectoryEntry(ZIP_CENTRAL_DIRECTORY_ENTRY *entry)
{
    OPENSSL_free(entry->fileName);
    OPENSSL_free(entry->extraField);
    OPENSSL_free(entry->fileComment);
    if (entry->overrideData) {
        OPENSSL_free(entry->overrideData->data);
    }
    OPENSSL_free(entry->overrideData);
    OPENSSL_free(entry);
}

/*
 * Read Zip end of central directory record
 * [out] eocdr: end of central directory record
 * [in] file: FILE pointer
 * [returns] 0 on error or 1 on success
 */
static int readZipEOCDR(ZIP_EOCDR *eocdr, FILE *file)
{
    char signature[4];
    size_t size;

    if (fseeko(file, -EOCDR_SIZE, SEEK_END) < 0) {
        return 0; /* FAILED */
    }
    size = fread(signature, 1, 4, file);
    if (size != 4) {
        return 0; /* FAILED */
    }
    if (memcmp(signature, PKZIP_EOCDR_SIGNATURE, 4)) {
        printf("The input file is not a valip zip file - could not find End of Central Directory record\n");
        return 0; /* FAILED */
    }
    /* number of this disk (2 bytes) */
    eocdr->diskNumber = fileGetU16(file);
    /* number of the disk with the start of the central directory (2 bytes) */
    eocdr->centralDirectoryDiskNumber = fileGetU16(file);
    /* total number of entries in the central directory on this disk (2 bytes) */
    eocdr->diskEntries = fileGetU16(file);
    /* total number of entries in the central directory (2 bytes) */
    eocdr->totalEntries = fileGetU16(file);
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    if (eocdr->totalEntries > UINT16_MAX) {
        printf("Corrupted total number of entries in the central directory : 0x%08X\n", eocdr->totalEntries);
        return 0; /* FAILED */
    }
    #pragma GCC diagnostic pop
    /* size of the central directory (4 bytes) */
    eocdr->centralDirectorySize = fileGetU32(file);
    /* offset of start of central directory with respect
     * to the starting disk number (4 bytes) */
    eocdr->centralDirectoryOffset = fileGetU32(file);
    /* .ZIP file comment length (2 bytes) */
    eocdr->commentLen = fileGetU16(file);
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    if (eocdr->commentLen > UINT16_MAX) {
        printf("Corrupted file comment length : 0x%08X\n", eocdr->commentLen);
        return 0; /* FAILED */
    }
    #pragma GCC diagnostic pop
#if 0
    if (eocdr->centralDirectoryDiskNumber > 1 || eocdr->diskNumber > 1 ||
        eocdr->centralDirectoryDiskNumber != eocdr->diskNumber ||
        eocdr->diskEntries != eocdr->totalEntries)
    {
        printf("The input file is a multipart archive - not supported\n");
        return 0; /* FAILED */
    }
#endif
    if (eocdr->commentLen > 0) {
        eocdr->comment = OPENSSL_zalloc(eocdr->commentLen + 1);
        size = fread(eocdr->comment, 1, eocdr->commentLen, file);
        if (size != eocdr->commentLen) {
            return 0; /* FAILED */
        }
    } else {
        eocdr->comment = NULL;
    }
    return 1; /* OK */
}

/*
 * Read Zip64 end of central directory locator
 * [out] locator: Zip64 end of central directory locator
 * [in] file: FILE pointer
 * [returns] 0 on error or 1 on success
 */
static int readZip64EOCDLocator(ZIP64_EOCD_LOCATOR *locator, FILE *file)
{
    char signature[4];
    size_t size;

    if (fseeko(file, -(EOCDR_SIZE + ZIP64_EOCD_LOCATOR_SIZE), SEEK_END) < 0) {
        return 0; /* FAILED */
    }
    size = fread(signature, 1, 4, file);
    if (size != 4) {
        return 0; /* FAILED */
    }
    if (memcmp(signature, PKZIP64_EOCD_LOCATOR_SIGNATURE, 4)) {
        printf("The input file is not a valip zip file - could not find zip64 EOCD locator\n");
        return 0; /* FAILED */
    }
    locator->diskWithEOCD = fileGetU32(file);
    locator->eocdOffset = fileGetU64(file);
    locator->totalNumberOfDisks = fileGetU32(file);
    return 1; /* OK */
}

/*
 * Read Zip64 end of central directory record
 * [out] eocdr: Zip64 end of central directory record
 * [in] file: FILE pointer
 * [in] offset: eocdr struct offset in the file
 * [returns] 0 on error or 1 on success
 */
static int readZip64EOCDR(ZIP64_EOCDR *eocdr, FILE *file, uint64_t offset)
{
    char signature[4];
    size_t size;

    if (fseeko(file, (int64_t)offset, SEEK_SET) < 0) {
        return 0; /* FAILED */
    }
    size = fread(signature, 1, 4, file);
    if (size != 4) {
        return 0; /* FAILED */
    }
    if (memcmp(signature, PKZIP64_EOCDR_SIGNATURE, 4)) {
        printf("The input file is not a valip zip file - could not find zip64 End of Central Directory record\n");
        return 0; /* FAILED */
    }
    /* size of zip64 end of central directory record (8 bytes) */
    eocdr->eocdrSize = fileGetU64(file);
    /* version made by (2 bytes) */
    eocdr->creatorVersion = fileGetU16(file);
    /* version needed to extract (2 bytes) */
    eocdr->viewerVersion = fileGetU16(file);
    /* number of this disk (4 bytes) */
    eocdr->diskNumber = fileGetU32(file);
    /* number of the disk with the start of the central directory (4 bytes) */
    eocdr->diskWithCentralDirectory = fileGetU32(file);
    /* total number of entries in the central directory on this disk (8 bytes) */
    eocdr->diskEntries = fileGetU64(file);
    /* total number of entries in the central directory (8 bytes) */
    eocdr->totalEntries = fileGetU64(file);
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    if (eocdr->totalEntries > UINT64_MAX) {
        printf("Corrupted total number of entries in the central directory : 0x%08lX\n", eocdr->totalEntries);
        return 0; /* FAILED */
    }
    #pragma GCC diagnostic pop
    /* size of the central directory (8 bytes) */
    eocdr->centralDirectorySize = fileGetU64(file);
    /* offset of start of central directory with respect
     * to the starting disk number (8 bytes) */
    eocdr->centralDirectoryOffset = fileGetU64(file);
    /* zip64 extensible data sector (comment) */
    eocdr->commentLen = eocdr->eocdrSize - 44;
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    if (eocdr->commentLen > UINT16_MAX) {
        printf("Corrupted file comment length : 0x%08lX\n", eocdr->commentLen);
        return 0; /* FAILED */
    }
    #pragma GCC diagnostic pop
    if (eocdr->commentLen > 0) {
        eocdr->comment = OPENSSL_malloc(eocdr->commentLen);
        size = fread(eocdr->comment, 1, eocdr->commentLen, file);
        if (size != eocdr->commentLen) {
            return 0; /* FAILED */
        }
    }
    if (eocdr->diskWithCentralDirectory > 1 || eocdr->diskNumber > 1 ||
        eocdr->diskWithCentralDirectory != eocdr->diskNumber ||
        eocdr->totalEntries != eocdr->diskEntries) {
        printf("The input file is a multipart archive - not supported\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

static uint64_t fileGetU64(FILE *file)
{
    uint64_t l = fileGetU32(file);
    uint64_t h = fileGetU32(file);
    return h << 32 | l;
}

static uint32_t fileGetU32(FILE *file)
{
    uint8_t b[4];
    size_t size = fread(b, 1, 4, file);
    if (size != 4) {
        return 0; /* FAILED */
    }
    return (uint32_t)(b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]);
}

static uint16_t fileGetU16(FILE *file)
{
    uint8_t b[2];
    size_t size = fread(b, 1, 2, file);
    if (size != 2) {
        return 0; /* FAILED */
    }
    return (uint16_t)(b[1] << 8 | b[0]);
}

static uint64_t bufferGetU64(uint8_t *buffer, uint64_t *pos)
{
    uint64_t l = bufferGetU32(buffer, pos);
    uint64_t h = bufferGetU32(buffer, pos);
    return h << 32 | l;
}

static uint32_t bufferGetU32(uint8_t *buffer, uint64_t *pos)
{
    uint32_t ret = (uint32_t)(buffer[*pos + 3] << 24 | \
                              buffer[*pos + 2] << 16 | \
                              buffer[*pos + 1] << 8 | \
                              buffer[*pos]);
    *pos += 4;
    return ret;
}

static uint16_t bufferGetU16(uint8_t *buffer, uint64_t *pos)
{
    uint16_t ret = (uint16_t)(buffer[*pos + 1] << 8 | buffer[*pos]);
    *pos += 2;
    return ret;
}

void bioAddU64(BIO *bio, uint64_t v)
{
    uint32_t l = v & UINT32_MAX;
    uint32_t h = (uint32_t)(v >> 32);
    bioAddU32(bio, l);
    bioAddU32(bio, h);
}

static void bioAddU32(BIO *bio, uint32_t v)
{
    uint8_t b[4];
    b[0] = (u_char)((v) & UINT8_MAX);
    b[1] = (u_char)(((v) >> 8) & UINT8_MAX);
    b[2] = (u_char)(((v) >> 16) & UINT8_MAX);
    b[3] = (u_char)(((v) >> 24) & UINT8_MAX);
    BIO_write(bio, b, 4);
}

static void bioAddU16(BIO *bio, uint16_t v)
{
    uint8_t b[2];
    b[0] = (u_char)((v) & UINT8_MAX);
    b[1] = (u_char)(((v) >> 8) & UINT8_MAX);
    BIO_write(bio, b, 2);
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: nil
End:

  vim: set ts=4 expandtab:
*/
