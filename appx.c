/*
 * APPX file support library
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 *
 * Copyright (C) Maciej Panek <maciej.panek_malpa_punxworks.com>
 * Copyright (C) 2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
  * APPX files do not support nesting (multiple signature)
 */

#define _FILE_OFFSET_BITS 64

#include "osslsigncode.h"
#include "helpers.h"

#include <zlib.h>
#include <inttypes.h>

#ifndef PRIX64
#if defined(_MSC_VER)
#define PRIX64 "I64X"
#else /* _MSC_VER */
#if ULONG_MAX == 0xFFFFFFFFFFFFFFFF
#define PRIX64 "lX"
#else /* ULONG_MAX == 0xFFFFFFFFFFFFFFFF */
#define PRIX64 "llX"
#endif /* ULONG_MAX == 0xFFFFFFFFFFFFFFFF */
#endif /* _MSC_VER */
#endif /* PRIX64 */

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
static const char *APPXBUNDLE_MANIFEST_FILENAME = "AppxMetadata/AppxBundleManifest.xml";
static const char *CODE_INTEGRITY_FILENAME = "AppxMetadata/CodeIntegrity.cat";
static const char *SIGNATURE_CONTENT_TYPES_ENTRY = "<Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/>";
static const char *SIGNATURE_CONTENT_TYPES_CLOSING_TAG = "</Types>";
static const u_char APPX_UUID[] = { 0x4B, 0xDF, 0xC5, 0x0A, 0x07, 0xCE, 0xE2, 0x4D, 0xB7, 0x6E, 0x23, 0xC8, 0x39, 0xA0, 0x9F, 0xD1 };
static const u_char APPXBUNDLE_UUID[] = { 0xB3, 0x58, 0x5F, 0x0F, 0xDE, 0xAA, 0x9A, 0x4B, 0xA4, 0x34, 0x95, 0x74, 0x2D, 0x92, 0xEC, 0xEB };

static const char PKCX_SIGNATURE[4] = { 'P', 'K', 'C', 'X' }; /* P7X format header */
static const char APPX_SIGNATURE[4] = { 'A', 'P', 'P', 'X' }; /* APPX header */
static const char AXPC_SIGNATURE[4] = { 'A', 'X', 'P', 'C' }; /* digest of zip file records */
static const char AXCD_SIGNATURE[4] = { 'A', 'X', 'C', 'D' }; /* digest zip file central directory */
static const char AXCT_SIGNATURE[4] = { 'A', 'X', 'C', 'T' }; /* digest of uncompressed [ContentTypes].xml */
static const char AXBM_SIGNATURE[4] = { 'A', 'X', 'B', 'M' }; /* digest of uncompressed AppxBlockMap.xml */
static const char AXCI_SIGNATURE[4] = { 'A', 'X', 'C', 'I' }; /* digest of uncompressed AppxMetadata/CodeIntegrity.cat (optional) */

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

DEFINE_STACK_OF(ZIP_CENTRAL_DIRECTORY_ENTRY)

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
    int hashlen;
} appx_ctx_t;

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *appx_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static const EVP_MD *appx_md_get(FILE_FORMAT_CTX *ctx);
static ASN1_OBJECT *appx_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static PKCS7 *appx_pkcs7_contents_get(FILE_FORMAT_CTX *ctx, BIO *hash, const EVP_MD *md);
static int appx_hash_length_get(FILE_FORMAT_CTX *ctx);
static int appx_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *appx_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static int appx_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int appx_process_data(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *appx_pkcs7_signature_new(FILE_FORMAT_CTX *ctx, BIO *hash);
static int appx_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static void appx_bio_free(BIO *hash, BIO *outdata);
static void appx_ctx_cleanup(FILE_FORMAT_CTX *ctx);

FILE_FORMAT file_format_appx = {
    .ctx_new = appx_ctx_new,
    .md_get = appx_md_get,
    .data_blob_get = appx_spc_sip_info_get,
    .pkcs7_contents_get = appx_pkcs7_contents_get,
    .hash_length_get = appx_hash_length_get,
    .verify_digests = appx_verify_digests,
    .pkcs7_extract = appx_pkcs7_extract,
    .remove_pkcs7 = appx_remove_pkcs7,
    .process_data = appx_process_data,
    .pkcs7_signature_new = appx_pkcs7_signature_new,
    .append_pkcs7 = appx_append_pkcs7,
    .bio_free = appx_bio_free,
    .ctx_cleanup = appx_ctx_cleanup,
};

/* Prototypes */
static BIO *appx_calculate_hashes(FILE_FORMAT_CTX *ctx);
static BIO *appx_hash_blob_get(FILE_FORMAT_CTX *ctx);
static uint8_t *appx_calc_zip_central_directory_hash(ZIP_FILE *zip, const EVP_MD *md, uint64_t cdOffset);
static int appx_write_central_directory(BIO *bio, ZIP_FILE *zip, int removeSignature, uint64_t cdOffset);
static uint8_t *appx_calc_zip_data_hash(uint64_t *cdOffset, ZIP_FILE *zip, const EVP_MD *md);
static int appx_extract_hashes(FILE_FORMAT_CTX *ctx, SpcIndirectDataContent *content);
static int appx_compare_hashes(FILE_FORMAT_CTX *ctx);
static int appx_remove_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static int appx_append_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static const EVP_MD *appx_get_md(ZIP_FILE *zip);
static ZIP_CENTRAL_DIRECTORY_ENTRY *zipGetCDEntryByName(ZIP_FILE *zip, const char *name);
static void zipWriteCentralDirectoryEntry(BIO *bio, uint64_t *sizeOnDisk, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint64_t offsetDiff);
static int zipAppendSignatureFile(BIO *bio, ZIP_FILE *zip, uint8_t *data, uint64_t dataSize);
static int zipOverrideFileData(ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint8_t *data, uint64_t dataSize);
static int zipRewriteData(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, BIO *bio, uint64_t *sizeOnDisk);
static void zipWriteLocalHeader(BIO *bio, uint64_t *sizeonDisk, ZIP_LOCAL_HEADER *header);
static int zipEntryExist(ZIP_FILE *zip, const char *name);
static u_char *zipCalcDigest(ZIP_FILE *zip, const char *fileName, const EVP_MD *md);
static size_t zipReadFileDataByName(uint8_t **pData, ZIP_FILE *zip, const char *name);
static size_t zipReadFileData(ZIP_FILE *zip, uint8_t **pData, ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static int zipReadLocalHeader(ZIP_LOCAL_HEADER *header, ZIP_FILE *zip, uint64_t compressedSize);
static int zipInflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong *sourceLen);
static int zipDeflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong sourceLen);
static ZIP_FILE *openZip(const char *filename);
static void freeZip(ZIP_FILE *zip);
static ZIP_FILE *zipSortCentralDirectory(ZIP_FILE *zip);
static void zipPrintCentralDirectory(ZIP_FILE *zip);
static int zipReadCentralDirectory(ZIP_FILE *zip, FILE *file);
static ZIP_CENTRAL_DIRECTORY_ENTRY *zipReadNextCentralDirectoryEntry(FILE *file);
static void freeZipCentralDirectoryEntry(ZIP_CENTRAL_DIRECTORY_ENTRY *entry);
static int readZipEOCDR(ZIP_EOCDR *eocdr, FILE *file);
static int readZip64EOCDLocator(ZIP64_EOCD_LOCATOR *locator, FILE *file);
static int readZip64EOCDR(ZIP64_EOCDR *eocdr, FILE *file, uint64_t offset);
static int get_current_position(BIO *bio, uint64_t *offset);
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
    if (zipGetCDEntryByName(zip, APPXBUNDLE_MANIFEST_FILENAME)) {
        ctx->appx_ctx->isBundle = 1;
    }
    if (options->cmd == CMD_SIGN || options->cmd==CMD_ATTACH
        || options->cmd==CMD_ADD || options->cmd == CMD_EXTRACT_DATA) {
        printf("Warning: Ignore -h option, use the hash algorithm specified in AppxBlockMap.xml\n");
    }
    if (options->pagehash == 1)
        printf("Warning: -ph option is only valid for PE files\n");
    if (options->jp >= 0)
        printf("Warning: -jp option is only valid for CAB files\n");
    if (options->add_msi_dse == 1)
        printf("Warning: -add-msi-dse option is only valid for MSI files\n");
    return ctx;
}

/*
 * Return a hash algorithm specified in the AppxBlockMap.xml file.
 * [in] ctx: structure holds input and output data
 * [returns] hash algorithm
 */
static const EVP_MD *appx_md_get(FILE_FORMAT_CTX *ctx)
{
    return ctx->appx_ctx->md;
}

/*
 * Allocate and return SpcSipInfo object.
 * [out] p: SpcSipInfo data
 * [out] plen: SpcSipInfo data length
 * [in] ctx: structure holds input and output data
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_SIPINFO_OBJID
 */
static ASN1_OBJECT *appx_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
    ASN1_OBJECT *dtype;
    AppxSpcSipInfo *si = AppxSpcSipInfo_new();

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
 * Allocate and return a data content to be signed.
 * [in] ctx: structure holds input and output data
 * [in] hash: message digest BIO
 * [in] md: message digest algorithm
 * [returns] data content
 */
static PKCS7 *appx_pkcs7_contents_get(FILE_FORMAT_CTX *ctx, BIO *hash, const EVP_MD *md)
{
    ASN1_OCTET_STRING *content;
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    BIO *bhash;

    /* squash unused parameter warnings */
    (void)md;
    (void)hash;

    /* Create and append a new signature content types entry */
    entry = zipGetCDEntryByName(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME);
    if (!entry) {
        fprintf(stderr, "Not a valid .appx file: content types file missing\n");
        return NULL; /* FAILED */
    }
    if (!appx_append_ct_signature_entry(ctx->appx_ctx->zip, entry)) {
        return NULL; /* FAILED */
    }
    bhash = appx_calculate_hashes(ctx);
    if (!bhash) {
        return NULL; /* FAILED */
    }
    content = spc_indirect_data_content_get(bhash, ctx);
    BIO_free_all(bhash);
    return pkcs7_set_content(content);
}

/*
 * Get concatenated hashes length.
 * [in] ctx: structure holds input and output data
 * [returns] the length of concatenated hashes
 */
static int appx_hash_length_get(FILE_FORMAT_CTX *ctx)
{
    return ctx->appx_ctx->hashlen;
}

/*
 * Calculate message digest and compare to value retrieved from PKCS#7 signedData.
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
            BIO *hashes;
            if (!appx_extract_hashes(ctx, idc)) {
                fprintf(stderr, "Failed to extract hashes from the signature\n");
                SpcIndirectDataContent_free(idc);
                return 0; /* FAILED */
            }
            hashes = appx_calculate_hashes(ctx);
            if (!hashes) {
                SpcIndirectDataContent_free(idc);
                return 0; /* FAILED */
            }
            BIO_free_all(hashes);
            if (!appx_compare_hashes(ctx)) {
                fprintf(stderr, "Signature hash verification failed\n");
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
    size_t dataSize;

    /* Check if the signature exists */
    if (!zipEntryExist(ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME)) {
        fprintf(stderr, "%s does not exist\n", APP_SIGNATURE_FILENAME);
        return NULL; /* FAILED */
    }
    dataSize = zipReadFileDataByName(&data, ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME);
    if (dataSize <= 0) {
        return NULL; /* FAILED */
    }
    /* P7X format is just 0x504B4358 (PKCX) followed by PKCS#7 data in the DER format */
    if (memcmp(data, PKCX_SIGNATURE, 4)) {
        fprintf(stderr, "Invalid PKCX header\n");
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
    uint8_t *data = NULL;
    size_t dataSize;
    uint64_t cdOffset, noEntries = 0;
    ZIP_FILE *zip = ctx->appx_ctx->zip;
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry = zipGetCDEntryByName(zip, CONTENT_TYPES_FILENAME);

    /* squash the unused parameter warning */
    (void)hash;

    if (!entry) {
        fprintf(stderr, "Not a valid .appx file: content types file missing\n");
        return 1; /* FAILED */
    }
    /* read signature data */
    dataSize = zipReadFileDataByName(&data, ctx->appx_ctx->zip, APP_SIGNATURE_FILENAME);
    if (dataSize <= 0) {
        return 1; /* FAILED, no signature */
    }
    OPENSSL_free(data);
    if (!appx_remove_ct_signature_entry(zip, entry)) {
        fprintf(stderr, "Failed to remove signature entry\n");
        return 1; /* FAILED */
    }
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (noEntries == zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            return 1; /* FAILED */
        }
        noEntries++;
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            return 1; /* FAILED */
        }
        if (strcmp(entry->fileName, APP_SIGNATURE_FILENAME)) {
            uint64_t dummy;
            if (!zipRewriteData(zip, entry, outdata, &dummy)) {
                return 1; /* FAILED */
            }
        }
    }
    if (!get_current_position(outdata, &cdOffset)) {
        fprintf(stderr, "Unable to get offset\n");
        return 1; /* FAILED */
    }
    if (!appx_write_central_directory(outdata, zip, 1, cdOffset)) {
        fprintf(stderr, "Unable to write central directory\n");
        return 1; /* FAILED */
    }
    return 0; /* OK */
}

/*
 * Modify specific type data.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [out] outdata: outdata file BIO (unused)
 * [returns] 1 on error or 0 on success
 */
static int appx_process_data(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;

    /* squash unused parameter warnings */
    (void)outdata;
    (void)hash;

    /* Create and append a new signature content types entry */
    entry = zipGetCDEntryByName(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME);
    if (!entry) {
        fprintf(stderr, "Not a valid .appx file: content types file missing\n");
        return 0; /* FAILED */
    }
    if (!appx_append_ct_signature_entry(ctx->appx_ctx->zip, entry)) {
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Create a new PKCS#7 signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *appx_pkcs7_signature_new(FILE_FORMAT_CTX *ctx, BIO *hash)
{
    ASN1_OCTET_STRING *content;
    PKCS7 *p7 = NULL;
    BIO *hashes;

    /* squash unused parameter warnings */
    (void)hash;

    /* Create hash blob from concatenated APPX hashes */
    hashes = appx_calculate_hashes(ctx);
    if (!hashes) {
        return NULL; /* FAILED */
    }
    p7 = pkcs7_create(ctx);
    if (!p7) {
        fprintf(stderr, "Creating a new signature failed\n");
        BIO_free_all(hashes);
        return NULL; /* FAILED */
    }
    if (!add_indirect_data_object(p7)) {
        fprintf(stderr, "Adding SPC_INDIRECT_DATA_OBJID failed\n");
        PKCS7_free(p7);
        BIO_free_all(hashes);
        return NULL; /* FAILED */
    }
    content = spc_indirect_data_content_get(hashes, ctx);
    BIO_free_all(hashes);
    if (!content) {
        fprintf(stderr, "Failed to get spcIndirectDataContent\n");
        PKCS7_free(p7);
        return NULL; /* FAILED */
    }
    if (!sign_spc_indirect_data_content(p7, content)) {
        fprintf(stderr, "Failed to set signed content\n");
        PKCS7_free(p7);
        ASN1_OCTET_STRING_free(content);
        return NULL; /* FAILED */
    }
    ASN1_OCTET_STRING_free(content);
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
    uint64_t cdOffset, noEntries = 0;

    for (entry = zip->centralDirectoryHead; entry != NULL;) {
        if (noEntries >= zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            return 1; /* FAILED */
        }
        noEntries++;
        last = entry;
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            return 1; /* FAILED */
        }
        if (strcmp(entry->fileName, APP_SIGNATURE_FILENAME)) {
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
    if (!zipAppendSignatureFile(outdata, zip, blob, (uint64_t)len)) {
        OPENSSL_free(blob);
        fprintf(stderr, "Failed to append zip file\n");
        return 1; /* FAILED */
    }
    OPENSSL_free(der);
    OPENSSL_free(blob);
    if (!get_current_position(outdata, &cdOffset)) {
        fprintf(stderr, "Unable to get offset\n");
        return 1; /* FAILED */
    }
    if (!appx_write_central_directory(outdata, zip, 0, cdOffset)) {
        fprintf(stderr, "Unable to write central directory\n");
        return 1; /* FAILED */
    }
    return 0; /* OK */
}

/*
 * Free up an entire message digest BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] none
 */
static void appx_bio_free(BIO *hash, BIO *outdata)
{
    BIO_free_all(outdata);
    BIO_free_all(hash);
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and PE format specific structure.
 * [out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] none
 */
static void appx_ctx_cleanup(FILE_FORMAT_CTX *ctx)
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

/*
 * APPX helper functions
 */

/*
 * Calculate ZIP hashes.
 * [in, out] ctx: structure holds input and output data
 * [returns] pointer to BIO with calculated APPX hashes
 */
static BIO *appx_calculate_hashes(FILE_FORMAT_CTX *ctx)
{
    uint64_t cdOffset = 0;

    ctx->appx_ctx->calculatedBMHash = zipCalcDigest(ctx->appx_ctx->zip, BLOCK_MAP_FILENAME, ctx->appx_ctx->md);
    ctx->appx_ctx->calculatedCTHash = zipCalcDigest(ctx->appx_ctx->zip, CONTENT_TYPES_FILENAME, ctx->appx_ctx->md);
    ctx->appx_ctx->calculatedDataHash = appx_calc_zip_data_hash(&cdOffset, ctx->appx_ctx->zip, ctx->appx_ctx->md);
    ctx->appx_ctx->calculatedCDHash = appx_calc_zip_central_directory_hash(ctx->appx_ctx->zip, ctx->appx_ctx->md, cdOffset);
    ctx->appx_ctx->calculatedCIHash = zipCalcDigest(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME, ctx->appx_ctx->md);

    if (!ctx->appx_ctx->calculatedBMHash || !ctx->appx_ctx->calculatedCTHash
        || !ctx->appx_ctx->calculatedCDHash || !ctx->appx_ctx->calculatedDataHash) {
        fprintf(stderr, "One or more hashes calculation failed\n");
        return NULL; /* FAILED */
    }
    if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->calculatedCIHash) {
        fprintf(stderr, "Code integrity file exists, but CI hash calculation failed\n");
        return NULL; /* FAILED */
    }
    return appx_hash_blob_get(ctx);
}

/*
 * Create hash blob from concatenated APPX hashes.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to BIO with calculated APPX hashes
 */
static BIO *appx_hash_blob_get(FILE_FORMAT_CTX *ctx)
{
    int mdlen = EVP_MD_size(ctx->appx_ctx->md);
    int dataSize = ctx->appx_ctx->calculatedCIHash ? 4 + 5 * (mdlen + 4) : 4 + 4 * (mdlen + 4);
    u_char *data = OPENSSL_malloc((size_t)dataSize);
    int pos = 0;
    BIO *hashes = BIO_new(BIO_s_mem());

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
    if (ctx->options->verbose) {
        print_hash("Hash of file: ", "\n", data, pos);
    }
    ctx->appx_ctx->hashlen = BIO_write(hashes, data, pos);
    OPENSSL_free(data);
    return hashes;
}

/*
 * Calculate ZIP central directory hash.
 * [in] zip: structure holds specific ZIP data
 * [in] md: message digest algorithm type
 * [in] cdOffset: central directory offset
 * [returns] hash
 */
static uint8_t *appx_calc_zip_central_directory_hash(ZIP_FILE *zip, const EVP_MD *md, uint64_t cdOffset)
{
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    if (!BIO_set_md(bhash, md)) {
        fprintf(stderr, "Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    BIO_push(bhash, BIO_new(BIO_s_null()));
    if (!appx_write_central_directory(bhash, zip, 1, cdOffset)) {
        fprintf(stderr, "Unable to write central directory\n");
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    return mdbuf;
}

/*
 * Write central directory structure.
 * [out] bio: outdata file BIO
 * [in] zip: structure holds specific ZIP data
 * [in] removeSignature: remove signature switch
 * [in] cdOffset: central directory offset
 * [returns] 0 on error or 1 on success
 */
static int appx_write_central_directory(BIO *bio, ZIP_FILE *zip, int removeSignature, uint64_t cdOffset)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    uint64_t offsetDiff = 0, cdSize = 0;
    uint16_t noEntries = 0;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        /* the signature file is considered nonexistent for hashing purposes */
        uint64_t sizeOnDisk = 0;
        if (noEntries > zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            return 0; /* FAILED */
        }
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            return 0; /* FAILED */
        }
        if (removeSignature && !strcmp(entry->fileName, APP_SIGNATURE_FILENAME)) {
            continue;
        }
        /* APP_SIGNATURE is not 'tainted' by offset shift after replacing the contents of [content_types] */
        zipWriteCentralDirectoryEntry(bio, &sizeOnDisk, entry, strcmp(entry->fileName, APP_SIGNATURE_FILENAME) ? offsetDiff : 0);
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
                return 0; /* FAILED */
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
    return 1; /* OK */
}

/*
 * Calculate ZIP data hash.
 * [out] cdOffset: central directory offset
 * [in] zip: structure holds specific ZIP data
 * [in] md: message digest algorithm type
 * [returns] hash
 */
static uint8_t *appx_calc_zip_data_hash(uint64_t *cdOffset, ZIP_FILE *zip, const EVP_MD *md)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());
    uint64_t noEntries = 0;

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    if (!BIO_set_md(bhash, md)) {
        fprintf(stderr, "Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    BIO_push(bhash, BIO_new(BIO_s_null()));
    *cdOffset = 0;
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        /* the signature file is considered not existent for hashing purposes */
        uint64_t sizeOnDisk = 0;
        if (noEntries >= zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            BIO_free_all(bhash);
            return NULL; /* FAILED */
        }
        noEntries++;
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            BIO_free_all(bhash);
            return NULL; /* FAILED */
        }
        if (!strcmp(entry->fileName, APP_SIGNATURE_FILENAME)) {
            continue;
        }
        if (!zipRewriteData(zip, entry, bhash, &sizeOnDisk)) {
            fprintf(stderr, "Rewrite data error\n");
            BIO_free_all(bhash);
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
    const unsigned char *blob = content->data->value->value.sequence->data;
    d2i_AppxSpcSipInfo(&si, &blob, content->data->value->value.sequence->length);
    long a = ASN1_INTEGER_get(si->a);
    long b = ASN1_INTEGER_get(si->b);
    long c = ASN1_INTEGER_get(si->c);
    long d = ASN1_INTEGER_get(si->d);
    long e = ASN1_INTEGER_get(si->e);
    long f = ASN1_INTEGER_get(si->f);
    BIO *stdbio = BIO_new_fp(stderr, BIO_NOCLOSE);
    printf("a: 0x%lX b: 0x%lX c: 0x%lX d: 0x%lX e: 0x%lX f: 0x%lX\n", a, b, c, d, e, f);
    printf("string: ");
    ASN1_STRING_print_ex(stdbio, si->string, ASN1_STRFLGS_RFC2253);
    printf("\n\n");
    AppxSpcSipInfo_free(si);
    BIO_free_all(stdbio);
#endif
    int length = content->messageDigest->digest->length;
    uint8_t *data = content->messageDigest->digest->data;
    int mdlen = EVP_MD_size(ctx->appx_ctx->md);
    int pos = 4;

    /* we are expecting at least 4 hashes + 4 byte header */
    if (length < 4 * mdlen + 4) {
        fprintf(stderr, "Hash too short\n");
        return 0; /* FAILED */
    }
    if (memcmp(data, APPX_SIGNATURE, 4)) {
        fprintf(stderr, "Hash signature does not match\n");
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
            fprintf(stderr, "Invalid hash signature\n");
            return 0; /* FAILED */
        }
        pos += mdlen + 4;
    }
    if (!ctx->appx_ctx->existingDataHash) {
        fprintf(stderr, "File hash missing\n");
        return 0; /* FAILED */
    }
    if (!ctx->appx_ctx->existingCDHash) {
        fprintf(stderr, "Central directory hash missing\n");
        return 0; /* FAILED */
    }
    if (!ctx->appx_ctx->existingBMHash) {
        fprintf(stderr, "Block map hash missing\n");
        return 0; /* FAILED */
    }
    if (!ctx->appx_ctx->existingCTHash) {
        fprintf(stderr, "Content types hash missing\n");
        return 0; /* FAILED */
    }
    if (zipEntryExist(ctx->appx_ctx->zip, CODE_INTEGRITY_FILENAME) && !ctx->appx_ctx->existingCIHash) {
        fprintf(stderr, "Code integrity hash missing\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Compare extracted and calculated hashes.
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
        fprintf(stderr, "Block map hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedCTHash && ctx->appx_ctx->existingCTHash) {
        printf("Checking Content Types hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingCTHash, ctx->appx_ctx->calculatedCTHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        fprintf(stderr, "Content Types hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedDataHash && ctx->appx_ctx->existingDataHash) {
        printf("Checking Data hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingDataHash, ctx->appx_ctx->calculatedDataHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        fprintf(stderr, "Central Directory hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedCDHash && ctx->appx_ctx->existingCDHash) {
        printf("Checking Central Directory hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingCDHash, ctx->appx_ctx->calculatedCDHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else {
        fprintf(stderr, "Central Directory hash missing\n");
        return 0; /* FAILED */
    }
    if (ctx->appx_ctx->calculatedCIHash && ctx->appx_ctx->existingCIHash) {
        printf("Checking Code Integrity hashes:\n");
        if (!compare_digests(ctx->appx_ctx->existingCIHash, ctx->appx_ctx->calculatedCIHash, mdtype)) {
            return 0; /* FAILED */
        }
    } else if (!ctx->appx_ctx->calculatedCIHash && !ctx->appx_ctx->existingCIHash) {
        /* this is fine, CI file is optional -> if it is missing we expect both hashes to be nonexistent */
    } else {
        fprintf(stderr, "Code Integrity hash missing\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Remove signature content types entry.
 * [in] zip: structure holds specific ZIP data
 * [in, out] entry: central directory structure
 * [returns] 0 on error or 1 on success
 */
static int appx_remove_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry)
{
    uint8_t *data;
    const char *cpos;
    size_t dataSize, ipos, len;
    int ret;

    dataSize = zipReadFileData(zip, &data, entry);
    if (dataSize <= 0) {
        return 0; /* FAILED */
    }
    cpos = strstr((const char *)data, SIGNATURE_CONTENT_TYPES_ENTRY);
    if (!cpos) {
        printf("Warning: Did not find existing signature entry in %s\n", entry->fileName);
        OPENSSL_free(data);
        return 1; /* do not treat as en error */
    }
    /* *cpos > *data */
    ipos = (size_t)(cpos - (char *)data);
    len = strlen(SIGNATURE_CONTENT_TYPES_ENTRY);
    memmove(data + ipos, data + ipos + len, dataSize - ipos - len);
    dataSize -= len;
    ret = zipOverrideFileData(entry, data, (uint64_t)dataSize);
    OPENSSL_free(data);
    return ret;
}

/*
 * Append signature content types entry.
 * [in] zip: structure holds specific ZIP data
 * [in, out] entry: central directory structure
 * [returns] 0 on error or 1 on success
 */
static int appx_append_ct_signature_entry(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry)
{
    uint8_t *data, *newData;
    const char *existingEntry, *cpos;
    size_t dataSize, newSize, ipos, len;
    int ret;

    dataSize = zipReadFileData(zip, &data, entry);
    if (dataSize <= 0) {
        return 0; /* FAILED */
    }
    existingEntry = strstr((const char *)data, SIGNATURE_CONTENT_TYPES_ENTRY);
    if (existingEntry) {
        OPENSSL_free(data);
        return 1; /* do not append it twice */
    }
    cpos = strstr((const char *)data, SIGNATURE_CONTENT_TYPES_CLOSING_TAG);
    if (!cpos) {
        fprintf(stderr, "%s parsing error\n", entry->fileName);
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
    ret = zipOverrideFileData(entry, newData, (uint64_t)newSize);
    OPENSSL_free(data);
    OPENSSL_free(newData);
    return ret;
}

/*
 * Get a hash algorithm specified in the AppxBlockMap.xml file.
 * [in] zip: structure holds specific ZIP data
 * [returns] one of SHA256/SHA384/SHA512 digest algorithms
 */
static const EVP_MD *appx_get_md(ZIP_FILE *zip)
{
    uint8_t *data = NULL;
    char *start, *end, *pos;
    char *valueStart = NULL, *valueEnd = NULL;
    const EVP_MD *md = NULL;
    size_t slen, dataSize;

    dataSize = zipReadFileDataByName(&data, zip, BLOCK_MAP_FILENAME);
    if (dataSize <= 0) {
        fprintf(stderr, "Could not read: %s\n", BLOCK_MAP_FILENAME);
        return NULL; /* FAILED */
    }
    start = strstr((const char *)data, HASH_METHOD_TAG);
    if (!start) {
        fprintf(stderr, "Parse error: tag: %s not found in %s\n", HASH_METHOD_TAG, BLOCK_MAP_FILENAME);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    start += strlen(HASH_METHOD_TAG);
    if ((uint8_t *)start >= data + dataSize) {
        fprintf(stderr, "Parse error: data too short in %s\n", BLOCK_MAP_FILENAME);
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    end = strstr((const char *)start, ">");
    if (!end) {
        fprintf(stderr, "Parse error: end of tag not found in %s\n", BLOCK_MAP_FILENAME);
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
        fprintf(stderr, "Parse error: value parse error in %s\n", BLOCK_MAP_FILENAME);
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
    } else {
        fprintf(stderr, "Unsupported hash method\n");
        OPENSSL_free(data);
        return NULL; /* FAILED */
    }
    OPENSSL_free(data);
    return md;
}

/*
 * Get central directory structure entry.
 * [in] zip: structure holds specific ZIP data
 * [in] name: APPXBUNDLE_MANIFEST_FILENAME or CONTENT_TYPES_FILENAME
 * [returns] pointer to central directory structure
 */
static ZIP_CENTRAL_DIRECTORY_ENTRY *zipGetCDEntryByName(ZIP_FILE *zip, const char *name)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    uint64_t noEntries = 0;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (noEntries >= zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            return NULL; /* FAILED */
        }
        noEntries++;
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            return NULL; /* FAILED */
        }
        if (!strcmp(entry->fileName, name)) {
            return entry;
        }
    }
    return NULL; /* FAILED */
}

/*
 * Write central directory entry.
 * [out] bio: outdata file BIO
 * [out] sizeOnDisk: size of central directory structure
 * [in] entry: central directory structure
 * [in] offsetDiff: central directory offset
 * [returns] none
 */
static void zipWriteCentralDirectoryEntry(BIO *bio, uint64_t *sizeOnDisk, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint64_t offsetDiff)
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
        /* TODO, if override data, need to rewrite the extra field */
        BIO_write(bio, entry->extraField, entry->extraFieldLen);
    }
#endif
    if (entry->fileCommentLen > 0 && entry->fileComment) {
        BIO_write(bio, entry->fileComment, entry->fileCommentLen);
    }
    *sizeOnDisk = (uint64_t)46 + entry->fileNameLen + entry->extraFieldLen + entry->fileCommentLen;
}

/*
 * Append signature file blob to outdata bio.
 * [out] bio: outdata file BIO
 * [in] zip: structure holds specific ZIP data
 * [in] data: pointer to signature file blob
 * [in] dataSize: signature file blob length
 * [returns] 0 on error or 1 on success
 */
static int zipAppendSignatureFile(BIO *bio, ZIP_FILE *zip, uint8_t *data, uint64_t dataSize)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    ZIP_LOCAL_HEADER header;
    time_t tim;
    struct tm *timeinfo;
    uint64_t offset, crc, len, pos = 0, dummy = 0, written = 0;
    uint64_t size = dataSize, sizeToWrite = dataSize;
    uint8_t *dataToWrite = data;
    int ret;

    memset(&header, 0, sizeof(ZIP_LOCAL_HEADER));
    dataToWrite = OPENSSL_malloc(dataSize);
    ret = zipDeflate(dataToWrite, &size, data, dataSize);
    if (ret != Z_OK) {
        fprintf(stderr, "Zip deflate failed: %d\n", ret);
        OPENSSL_free(dataToWrite);
        return 0; /* FAILED */
    }
    sizeToWrite = size;

    time(&tim);
    timeinfo = localtime(&tim);

    header.version = 0x14;
    header.flags = 0;
    header.compression = COMPRESSION_DEFLATE;
    header.modTime = (uint16_t)(timeinfo->tm_hour << 11 | \
                                timeinfo->tm_min << 5 | \
                                timeinfo->tm_sec >> 1);
    header.modDate = (uint16_t)((timeinfo->tm_year - 80) << 9 | \
                                (timeinfo->tm_mon + 1) << 5 | \
                                timeinfo->tm_mday);

    size = dataSize;
    crc = crc32(0L, Z_NULL, 0);
    while (size > 0) {
        len = MIN(size, UINT32_MAX);
        crc = crc32(crc, data + pos, (uint32_t)len);
        pos += len;
        size -= len;
    }
    header.crc32 = (uint32_t)crc;
    header.uncompressedSize = dataSize;
    header.compressedSize = sizeToWrite;
    header.fileNameLen = (uint16_t)strlen(APP_SIGNATURE_FILENAME);
    /* this will be reassigned to CD entry and freed there */
    header.fileName = OPENSSL_zalloc(header.fileNameLen + 1);
    memcpy(header.fileName, APP_SIGNATURE_FILENAME, header.fileNameLen);
    header.extraField = NULL;
    header.extraFieldLen = 0;

    if (!get_current_position(bio, &offset)) {
        fprintf(stderr, "Unable to get offset\n");
        OPENSSL_free(header.fileName);
        header.fileName = NULL;
        OPENSSL_free(dataToWrite);
        return 0; /* FAILED */
    }
    zipWriteLocalHeader(bio, &dummy, &header);
    while (sizeToWrite > 0) {
        uint64_t toWrite = sizeToWrite < SIZE_64K ? sizeToWrite : SIZE_64K;
        size_t check;
        if (!BIO_write_ex(bio, dataToWrite + written, toWrite, &check)
            || check != toWrite) {
            OPENSSL_free(header.fileName);
            header.fileName = NULL;
            OPENSSL_free(dataToWrite);
            return 0; /* FAILED */
        }
        sizeToWrite -= toWrite;
        written += toWrite;
    }
    OPENSSL_free(dataToWrite);

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
    /* take ownership of the fileName pointer */
    entry->fileName = header.fileName;
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
 * Override file data.
 * [out] entry: central directory structure
 * [in] data: pointer to data
 * [in] dataSize: data size
 * [returns] 0 on error or 1 on success
 */
static int zipOverrideFileData(ZIP_CENTRAL_DIRECTORY_ENTRY *entry, uint8_t *data, uint64_t dataSize)
{
    uint64_t crc, len, pos = 0, size = dataSize;
    int ret;

    if (entry->overrideData) {
        OPENSSL_free(entry->overrideData->data);
        OPENSSL_free(entry->overrideData);
        entry->overrideData = NULL;
    }
    entry->overrideData = OPENSSL_malloc(sizeof(ZIP_OVERRIDE_DATA));
    entry->overrideData->data = OPENSSL_malloc(dataSize);

    crc = crc32(0L, Z_NULL, 0);
    while (size > 0) {
        len = MIN(size, UINT32_MAX);
        crc = crc32(crc, data + pos, (uint32_t)len);
        pos += len;
        size -= len;
    }
    entry->overrideData->crc32 = (uint32_t)crc;
    entry->overrideData->uncompressedSize = dataSize;

    size = dataSize;
    ret = zipDeflate(entry->overrideData->data, &size, data, dataSize);
    if (ret != Z_OK) {
        fprintf(stderr, "Zip deflate failed: %d\n", ret);
        return 0; /* FAILED */
    }
    entry->overrideData->compressedSize = size;
    return 1; /* OK */
}

/*
 * Rewrite data to outdata bio.
 * [in, out] zip: structure holds specific ZIP data
 * [out] entry: central directory structure
 * [out] bio: outdata file BIO
 * [out] sizeOnDisk: outdata size
 * [returns] 0 on error or 1 on success
 */
static int zipRewriteData(ZIP_FILE *zip, ZIP_CENTRAL_DIRECTORY_ENTRY *entry, BIO *bio, uint64_t *sizeOnDisk)
{
    size_t check;
    ZIP_LOCAL_HEADER header;
    int ret = 0;

    memset(&header, 0, sizeof(header));
    if (entry->offsetOfLocalHeader >= (uint64_t)zip->fileSize) {
        fprintf(stderr, "Corrupted relative offset of local header : 0x%08" PRIX64 "\n", entry->offsetOfLocalHeader);
        return 0; /* FAILED */
    }
    if (fseeko(zip->file, (int64_t)entry->offsetOfLocalHeader, SEEK_SET) < 0) {
        return 0; /* FAILED */
    }
    if (!zipReadLocalHeader(&header, zip, entry->compressedSize)) {
        goto out;
    }
    if (entry->overrideData) {
        header.compressedSize = entry->overrideData->compressedSize;
        header.uncompressedSize = entry->overrideData->uncompressedSize;
        header.crc32 = entry->overrideData->crc32;
    }
    zipWriteLocalHeader(bio, sizeOnDisk, &header);
    if (entry->overrideData) {
        if (!BIO_write_ex(bio, entry->overrideData->data, entry->overrideData->compressedSize, &check)
            || check != entry->overrideData->compressedSize) {
            goto out;
        }
        if (entry->compressedSize > (uint64_t)zip->fileSize - entry->offsetOfLocalHeader) {
            fprintf(stderr, "Corrupted compressedSize : 0x%08" PRIX64 "\n", entry->compressedSize);
            goto out;
        }
        if (fseeko(zip->file, (int64_t)entry->compressedSize, SEEK_CUR) < 0) {
            goto out;
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
                goto out;
            }
            if (!BIO_write_ex(bio, data, toWrite, &check)
                || check != toWrite) {
                OPENSSL_free(data);
                goto out;
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
                goto out;
            }
            *sizeOnDisk += 24;
        } else {
            if (fseeko(zip->file, 16, SEEK_CUR) < 0) {
                goto out;
            }
            *sizeOnDisk += 16;
        }
    }
    ret = 1; /* OK */
out:
    OPENSSL_free(header.fileName);
    OPENSSL_free(header.extraField);
    header.fileName = NULL;
    header.extraField = NULL;
    return ret;
}

/*
 * Write local file header to outdata bio.
 * [out] bio: outdata file BIO
 * [out] sizeonDisk: data size
 * [in] header: local file header structure
 * [returns] none
 */
static void zipWriteLocalHeader(BIO *bio, uint64_t *sizeonDisk, ZIP_LOCAL_HEADER *header)
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
 * Check if a given ZIP file exists.
 * [in] zip: structure holds specific ZIP data
 * [in] name: APP_SIGNATURE_FILENAME or CODE_INTEGRITY_FILENAME
 * [returns] 0 on error or 1 on success
 */
static int zipEntryExist(ZIP_FILE *zip, const char *name)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    uint64_t noEntries = 0;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (noEntries >= zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            return 0; /* FAILED */
        }
        noEntries++;
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            return 0; /* FAILED */
        }
        if (!strcmp(entry->fileName, name)) {
            return 1; /* OK */
        }
    }
    return 0; /* FAILED */
}

/*
 * Calculate ZIP container file hash.
 * [in] zip: structure holds specific ZIP data
 * [in] fileName: one of ZIP container file
 * [in] md: message digest algorithm type
 * [returns] hash
 */
static u_char *zipCalcDigest(ZIP_FILE *zip, const char *fileName, const EVP_MD *md)
{
    uint8_t *data = NULL;
    size_t dataSize;
    u_char *mdbuf = NULL;
    BIO *bhash;

    dataSize = zipReadFileDataByName(&data, zip, fileName);
    if (dataSize <= 0) {
        return NULL; /* FAILED */
    }
    bhash = BIO_new(BIO_f_md());
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    if (!BIO_set_md(bhash, md)) {
        fprintf(stderr, "Unable to set the message digest of BIO\n");
        OPENSSL_free(data);
        BIO_free_all(bhash);
        return NULL; /* FAILED */
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
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
 * Read file data by name.
 * [out] pData: pointer to data
 * [in] zip: structure holds specific ZIP data
 * [in] name: one of ZIP container file
 * [returns] 0 on error or data size on success
 */
static size_t zipReadFileDataByName(uint8_t **pData, ZIP_FILE *zip, const char *name)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    uint64_t noEntries = 0;

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (noEntries >= zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            return 0; /* FAILED */
        }
        noEntries++;
        if (!entry->fileName || (entry->fileNameLen == 0)) {
            fprintf(stderr, "Corrupted file name\n");
            return 0; /* FAILED */
        }
        if (!strcmp(entry->fileName, name)) {
            return zipReadFileData(zip, pData, entry);
        }
    }
    return 0; /* FAILED */
}

/*
 * Read file data.
 * [in, out] zip: structure holds specific ZIP data
 * [out] pData: pointer to data
 * [in] entry: central directory structure
 * [returns] 0 on error or data size on success
 */
static size_t zipReadFileData(ZIP_FILE *zip, uint8_t **pData, ZIP_CENTRAL_DIRECTORY_ENTRY *entry)
{
    FILE *file = zip->file;
    uint8_t *compressedData = NULL;
    uint64_t compressedSize = 0;
    uint64_t uncompressedSize = 0;
    size_t size, dataSize = 0;

    if (entry->offsetOfLocalHeader >= (uint64_t)zip->fileSize) {
        fprintf(stderr, "Corrupted relative offset of local header : 0x%08" PRIX64 "\n", entry->offsetOfLocalHeader);
        return 0; /* FAILED */
    }
    if (fseeko(file, (int64_t)entry->offsetOfLocalHeader, SEEK_SET) < 0) {
        return 0; /* FAILED */
    }
    if (entry->overrideData) {
        compressedSize = entry->overrideData->compressedSize;
        /* Validate sizes for safe allocation */
        if (compressedSize > (uint64_t)(SIZE_MAX - 1)) {
            fprintf(stderr, "Corrupted compressedSize : %" PRIu64"\n", compressedSize);
            return 0; /* FAILED */
        }
        uncompressedSize = entry->overrideData->uncompressedSize;
        compressedData = OPENSSL_zalloc(compressedSize + 1);
        memcpy(compressedData, entry->overrideData->data, compressedSize);
    } else {
        ZIP_LOCAL_HEADER header;
        compressedSize = entry->compressedSize;
        uncompressedSize = entry->uncompressedSize;
        memset(&header, 0, sizeof(header));
        if (!zipReadLocalHeader(&header, zip, compressedSize)) {
            OPENSSL_free(header.fileName);
            OPENSSL_free(header.extraField);
            header.fileName = NULL;
            header.extraField = NULL;
            return 0; /* FAILED */
        }
        if (header.fileNameLen != entry->fileNameLen
            || memcmp(header.fileName, entry->fileName, header.fileNameLen)
            || header.compressedSize != compressedSize
            || header.uncompressedSize != uncompressedSize
            || header.compression != entry->compression) {
            fprintf(stderr, "Local header does not match central directory entry\n");
            OPENSSL_free(header.fileName);
            OPENSSL_free(header.extraField);
            header.fileName = NULL;
            header.extraField = NULL;
            return 0; /* FAILED */
        }
        /* we don't really need those */
        OPENSSL_free(header.fileName);
        OPENSSL_free(header.extraField);
        header.fileName = NULL;
        header.extraField = NULL;

        /* Validate sizes for safe allocation */
        if (compressedSize > (uint64_t)(SIZE_MAX - 1)
            || compressedSize > (uint64_t)zip->fileSize - entry->offsetOfLocalHeader) {
            fprintf(stderr, "Corrupted compressedSize : %" PRIu64"\n", compressedSize);
            return 0; /* FAILED */
        }
        compressedData = OPENSSL_zalloc(compressedSize + 1);
        size = fread(compressedData, 1, compressedSize, file);
        if (size != compressedSize) {
            OPENSSL_free(compressedData);
            return 0; /* FAILED */
        }
        compressedData[compressedSize] = 0;
    }
    if (entry->compression == COMPRESSION_NONE) {
        if (compressedSize == 0) {
            OPENSSL_free(compressedData);
            return 0; /* FAILED */
        }
        *pData = compressedData;
        dataSize = compressedSize;
    } else if (entry->compression == COMPRESSION_DEFLATE) {
        uint8_t *uncompressedData;
        uint64_t destLen, sourceLen;
        int ret;

        /* Validate sizes for safe allocation */
        if (uncompressedSize > (uint64_t)(SIZE_MAX - 1)) {
            fprintf(stderr, "Corrupted uncompressedSize : %" PRIu64"\n", uncompressedSize);
            OPENSSL_free(compressedData);
            return 0; /* FAILED */
        }
        /* Detect suspicious compression ratio (zip bomb protection) */
        if (uncompressedSize > 1024 * 1024 && uncompressedSize / 100 >= compressedSize) {
              fprintf(stderr, "Error: suspicious compression ratio\n");
              OPENSSL_free(compressedData);
              return 0; /* FAILED */
        }
        uncompressedData = OPENSSL_zalloc(uncompressedSize + 1);
        destLen = uncompressedSize;
        sourceLen = compressedSize;

        ret = zipInflate(uncompressedData, &destLen, compressedData, (uLong *)&sourceLen);
        OPENSSL_free(compressedData);

        if (ret != Z_OK) {
            fprintf(stderr, "Data decompression failed, zlib error: %d\n", ret);
            OPENSSL_free(uncompressedData);
            return 0; /* FAILED */
        } else {
            if (destLen == 0) {
                OPENSSL_free(uncompressedData);
                return 0; /* FAILED */
            }
            *pData = uncompressedData;
            dataSize = destLen;
        }
    } else {
        fprintf(stderr, "Unsupported compression mode: %d\n", entry->compression);
        OPENSSL_free(compressedData);
        return 0; /* FAILED */
    }
    return dataSize;
}

/*
 * Read local file header from a ZIP file.
 * [out] header: local file header
 * [in, out] zip: structure holds specific ZIP data
 * [in] compressedSize: compressed size
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
        fprintf(stderr, "The input file is not a valid zip file - local header signature does not match\n");
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
    /* file name length (2 bytes) */
    header->fileNameLen = fileGetU16(file);
    /* extra file name length (2 bytes) */
    header->extraFieldLen = fileGetU16(file);
    /* file name (variable size) */
    if (header->fileNameLen > 0) {
        /* fileNameLen is uint16_t (ZIP spec, 2-byte field),
         * so fileNameLen + 1 cannot overflow size_t */
        header->fileName = OPENSSL_zalloc(header->fileNameLen + 1);
        size = fread(header->fileName, 1, header->fileNameLen, file);
        if (size != header->fileNameLen) {
            return 0; /* FAILED */
        }
        header->fileName[header->fileNameLen] = 0;
    } else {
        header->fileName = NULL;
    }
    /* extra field (variable size) */
    if (header->extraFieldLen > 0) {
        /* extraFieldLen is uint16_t (ZIP spec, 2-byte field),
         * so extraFieldLen + 1 cannot overflow size_t */
        header->extraField = OPENSSL_zalloc(header->extraFieldLen + 1);
        size = fread(header->extraField, 1, header->extraFieldLen, file);
        if (size != header->extraFieldLen) {
            return 0; /* FAILED */
        }
        header->extraField[header->extraFieldLen] = 0;
    } else {
        header->extraField = NULL;
    }
    if (header->flags & DATA_DESCRIPTOR_BIT) {
        /* Read data descriptor */
        int64_t offset = ftello(file);
        if (offset < 0 || offset >= zip->fileSize) {
            return 0; /* FAILED */
        }
        if (compressedSize > (uint64_t)(zip->fileSize - offset)) {
            fprintf(stderr, "Corrupted compressedSize : 0x%08" PRIX64 "\n", compressedSize);
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
            fprintf(stderr, "The input file is not a valid zip file - flags indicate data descriptor, but data descriptor signature does not match\n");
            OPENSSL_free(header->fileName);
            OPENSSL_free(header->extraField);
            header->fileName = NULL;
            header->extraField = NULL;
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
                fprintf(stderr, "Expected zip64 header in local header extra field, got : 0x%X\n", op);
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
                    fprintf(stderr, "Invalid zip64 local header entry\n");
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
                    fprintf(stderr, "Invalid zip64 local header entry\n");
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
 * see: uncompress2(), but windowBits is set to –15 for raw inflate
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
    const uInt max = (uInt)-1; /* 0xFFFFFFFF */
    uLong len, left;
     /* for detection of incomplete stream when *destLen == 0 */
    static u_char buf[] = { 0x00 };

    /* reset stream */
    memset(&stream, 0, sizeof stream);

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
        /* coverity[overrun-buffer-arg] max value 0xFFFFFFFF is intended */
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
 * see: compress2(), but windowBits is set to -15 for raw deflate
 * https://github.com/madler/zlib/blob/09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851/compress.c#L22
 * [out] dest: destination buffer
 * [out] destLen: actual size of the compressed buffer
 * [in] source: source buffer
 * [in] sourceLen: length of the source buffer
 * [in] level: deflateInit2 parameter (8)
 * [returns] returns ZIP error or Z_OK if success
 */
static int zipDeflate(uint8_t *dest, uint64_t *destLen, uint8_t *source, uLong sourceLen)
{
    z_stream stream;
    int err;
    const uInt max = (uInt)-1; /* 0xFFFFFFFF */
    uLong left;

    /* reset stream */
    memset(&stream, 0, sizeof stream);

    left = *destLen;
    *destLen = 0;
    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;
    stream.opaque = (voidpf)0;

    err = deflateInit2(&stream, 8, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    if (err != Z_OK) {
        deflateEnd(&stream);
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
        /* coverity[overrun-buffer-arg] max value 0xFFFFFFFF is intended */
        err = deflate(&stream, sourceLen ? Z_NO_FLUSH : Z_FINISH);
    } while (err == Z_OK);
#if 0
    deflate(&stream, Z_SYNC_FLUSH);
#endif
    *destLen = stream.total_out;
    deflateEnd(&stream);
    return err == Z_STREAM_END ? Z_OK : err;
}

/*
 * Open input file and create ZIP_FILE structure.
 * [in] filename: input file
 * [returns] pointer to ZIP_FILE structure
 */
static ZIP_FILE *openZip(const char *filename)
{
    ZIP_FILE *zip;
    FILE *file = fopen(filename, "rb");

    if (!file) {
        return NULL; /* FAILED */
    }
    /* oncde we read eocdr, comment might be allocated and we need to take care of it
     -> create the ZIP_FILE structure */
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
        if (zip->locator.eocdOffset >= (uint64_t)zip->fileSize) {
            fprintf(stderr, "Corrupted end of central directory locator offset : 0x%08" PRIX64 "\n", zip->locator.eocdOffset);
            freeZip(zip);
            return 0; /* FAILED */
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
        zip->centralDirectoryRecordCount = (uint64_t)zip->eocdr.totalEntries;
        if (zip->centralDirectoryRecordCount > UINT16_MAX) {
            fprintf(stderr, "Corrupted total number of entries in the central directory : 0x%08" PRIX64 "\n", zip->centralDirectoryRecordCount);
            freeZip(zip);
            return NULL; /* FAILED */
        }
    }
    if (zip->centralDirectoryOffset >= (uint64_t)zip->fileSize) {
        fprintf(stderr, "Corrupted central directory offset : 0x%08" PRIX64 "\n", zip->centralDirectoryOffset);
        freeZip(zip);
        return NULL; /* FAILED */
    }
    if (!zipReadCentralDirectory(zip, file)) {
        freeZip(zip);
        return NULL; /* FAILED */
    }
    return zipSortCentralDirectory(zip);
}

/*
 * Free up ZIP_FILE structure.
 * [in] ZIP_FILE structure
 * [returns] none
 */
static void freeZip(ZIP_FILE *zip)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry, *next = NULL;
    uint64_t noEntries = 0;

    fclose(zip->file);
    OPENSSL_free(zip->eocdr.comment);
    OPENSSL_free(zip->eocdr64.comment);
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = next) {
        if (noEntries > zip->centralDirectoryRecordCount) {
            printf("Warning: Corrupted central directory structure\n");
            freeZipCentralDirectoryEntry(entry);
            return;
        }
        noEntries++;
        next = entry->next;
        freeZipCentralDirectoryEntry(entry);
    }
    OPENSSL_free(zip);
}

/*
 * Offset comparison function.
 * [in] a_ptr, b_ptr: pointers to ZIP_CENTRAL_DIRECTORY_ENTRY structure
 * [returns] entries order
 */
static int entry_compare(const ZIP_CENTRAL_DIRECTORY_ENTRY *const *a, const ZIP_CENTRAL_DIRECTORY_ENTRY *const *b)
{
    return (*a)->offsetOfLocalHeader < (*b)->offsetOfLocalHeader ? -1 : 1;
}

/*
 * Sort central directory entries in ascending order by offset.
 * [in] zip:  ZIP_FILE structure
 * [returns] pointer to sorted ZIP_FILE structure
 */
static ZIP_FILE *zipSortCentralDirectory(ZIP_FILE *zip)
{
    uint64_t noEntries = 0;
    int i;
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    STACK_OF(ZIP_CENTRAL_DIRECTORY_ENTRY) *chain = sk_ZIP_CENTRAL_DIRECTORY_ENTRY_new(entry_compare);

    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (noEntries >= zip->centralDirectoryRecordCount) {
            fprintf(stderr, "Corrupted central directory structure\n");
            sk_ZIP_CENTRAL_DIRECTORY_ENTRY_free(chain);
            freeZip(zip);
            return NULL; /* FAILED */
        }
        noEntries++;
        if (!sk_ZIP_CENTRAL_DIRECTORY_ENTRY_push(chain, entry)) {
            fprintf(stderr, "Failed to add central directory entry\n");
            sk_ZIP_CENTRAL_DIRECTORY_ENTRY_free(chain);
            freeZip(zip);
            return NULL; /* FAILED */
        }
    }
    sk_ZIP_CENTRAL_DIRECTORY_ENTRY_sort(chain);
    zip->centralDirectoryHead = entry = sk_ZIP_CENTRAL_DIRECTORY_ENTRY_value(chain, 0);
    if (!entry) {
        fprintf(stderr, "Failed to get sorted central directory entry\n");
        sk_ZIP_CENTRAL_DIRECTORY_ENTRY_free(chain);
        freeZip(zip);
        return NULL; /* FAILED */
    }
    for (i=1; i<sk_ZIP_CENTRAL_DIRECTORY_ENTRY_num(chain); i++) {
        entry->next = sk_ZIP_CENTRAL_DIRECTORY_ENTRY_value(chain, i);
        entry = entry->next;
    }
    entry->next = NULL;
    sk_ZIP_CENTRAL_DIRECTORY_ENTRY_free(chain);

    return zip;
}

/*
 * Log additional output.
 * [in] ZIP_FILE structure
 * [returns] none
 */
static void zipPrintCentralDirectory(ZIP_FILE *zip)
{
    ZIP_CENTRAL_DIRECTORY_ENTRY *entry;
    uint64_t noEntries = 0;

    printf("Central directory entry count: %" PRIu64"\n", zip->centralDirectoryRecordCount);
    for (entry = zip->centralDirectoryHead; entry != NULL; entry = entry->next) {
        if (noEntries >= zip->centralDirectoryRecordCount) {
            printf("Warning: Corrupted central directory structure\n");
        }
        noEntries++;
        printf("Name: %s Compressed: %" PRIu64" Uncompressed: %" PRIu64" Offset: %" PRIu64"\n", entry->fileName,
            entry->compressedSize, entry->uncompressedSize, entry->offsetOfLocalHeader);
    }
}

/*
 * Read central directory.
 * [in, out] zip: structure holds specific ZIP data
 * [in, out] file: FILE pointer to the input file
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
            fprintf(stderr, "Corrupted central directory structure\n");
            OPENSSL_free(entry);
            return 0; /* FAILED */
        }
        prev = entry;
    }
    return 1; /* OK */
}

/*
 * Initialize central directory structure.
 * [in] file: FILE pointer to the input file
 * [returns] pointer to the central directory structure
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
        fprintf(stderr, "The input file is not a valid zip file - could not find Central Directory record\n");
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
    /* compressed size (4 bytes), 0xFFFFFFFF for ZIP64 format */
    entry->compressedSize = fileGetU32(file);
    /* uncompressed size (4 bytes), 0xFFFFFFFF for ZIP64 format */
    entry->uncompressedSize = fileGetU32(file);
    /* file name length (2 bytes) */
    entry->fileNameLen = fileGetU16(file);
    /* extra field length (2 bytes) */
    entry->extraFieldLen = fileGetU16(file);
    /* file comment length (2 bytes) */
    entry->fileCommentLen = fileGetU16(file);
    /* disk number start (2 bytes), 0xFFFFFFFF for ZIP64 format */
    entry->diskNoStart = fileGetU16(file);
    /* internal file attributes (2 bytes) */
    entry->internalAttr = fileGetU16(file);
    /* external file attributes (4 bytes) */
    entry->externalAttr = fileGetU32(file);
    /* relative offset of local header (4 bytes), 0xFFFFFFFF for ZIP64 format */
    entry->offsetOfLocalHeader = fileGetU32(file);
    /* file name (variable size) */
    if (entry->fileNameLen > 0) {
        /* fileNameLen is uint16_t (ZIP spec, 2-byte field),
         * so fileNameLen + 1 cannot overflow size_t */
        entry->fileName = OPENSSL_zalloc(entry->fileNameLen + 1);
        size = fread(entry->fileName, 1, entry->fileNameLen, file);
        if (size != entry->fileNameLen) {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
        entry->fileName[entry->fileNameLen] = 0;
    }
    /* extra field (variable size) */
    if (entry->extraFieldLen > 0) {
        /* extraFieldLen is uint16_t (ZIP spec, 2-byte field),
         * so extraFieldLen + 1 cannot overflow size_t */
        entry->extraField = OPENSSL_zalloc(entry->extraFieldLen + 1);
        size = fread(entry->extraField, 1, entry->extraFieldLen, file);
        if (size != entry->extraFieldLen) {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
        entry->extraField[entry->extraFieldLen] = 0;
    }
    /* file comment (variable size) */
    if (entry->fileCommentLen > 0) {
        /* fileCommentLen is uint16_t (ZIP spec, 2-byte field),
         * so fileCommentLen + 1 cannot overflow size_t */
        entry->fileComment = OPENSSL_zalloc(entry->fileCommentLen + 1);
        size = fread(entry->fileComment, 1, entry->fileCommentLen, file);
        if (size != entry->fileCommentLen) {
            freeZipCentralDirectoryEntry(entry);
            return NULL; /* FAILED */
        }
        entry->fileComment[entry->fileCommentLen] = 0;
    }
    if (entry->uncompressedSize == UINT32_MAX || entry->compressedSize == UINT32_MAX ||
        entry->offsetOfLocalHeader == UINT32_MAX || entry->diskNoStart == UINT16_MAX) {
        if (entry->extraFieldLen > 4) {
            uint64_t pos = 0;
            uint64_t len;
            uint16_t header = bufferGetU16(entry->extraField, &pos);

            if (header != ZIP64_HEADER) {
                fprintf(stderr, "Expected zip64 header in central directory extra field, got : 0x%X\n", header);
                freeZipCentralDirectoryEntry(entry);
                return NULL; /* FAILED */
            }
            len = bufferGetU16(entry->extraField, &pos);
            if (entry->uncompressedSize == UINT32_MAX) {
                if (len >= 8) {
                    entry->uncompressedSize = bufferGetU64(entry->extraField, &pos);
                    entry->uncompressedSizeInZip64 = 1;
                } else {
                    fprintf(stderr, "Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
            if (entry->compressedSize == UINT32_MAX) {
                if (len >= 16) {
                    entry->compressedSize = bufferGetU64(entry->extraField, &pos);
                    entry->compressedSizeInZip64 = 1;
                } else {
                    fprintf(stderr, "Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
            if (entry->offsetOfLocalHeader == UINT32_MAX) {
                if (len >= 24) {
                    entry->offsetOfLocalHeader = bufferGetU64(entry->extraField, &pos);
                    entry->offsetInZip64 = 1;
                } else {
                    fprintf(stderr, "Invalid zip64 central directory entry\n");
                    freeZipCentralDirectoryEntry(entry);
                    return NULL; /* FAILED */
                }
            }
            if (entry->diskNoStart == UINT16_MAX) {
                if (len >= 28) {
                    entry->diskNoStart = bufferGetU32(entry->extraField, &pos);
                    entry->diskNoInZip64 = 1;
                } else {
                    fprintf(stderr, "Invalid zip64 central directory entry\n");
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
 * Read Zip end of central directory record.
 * [out] eocdr: end of central directory record
 * [in, out] file: FILE pointer to the input file
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
        /* Not a valid ZIP file - could not find End of Central Directory record */
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
    /* size of the central directory (4 bytes) */
    eocdr->centralDirectorySize = fileGetU32(file);
    /* offset of start of central directory with respect
     * to the starting disk number (4 bytes) */
    eocdr->centralDirectoryOffset = fileGetU32(file);
    /* .ZIP file comment length (2 bytes) */
    eocdr->commentLen = fileGetU16(file);
#if 0
    if (eocdr->centralDirectoryDiskNumber > 1 || eocdr->diskNumber > 1 ||
        eocdr->centralDirectoryDiskNumber != eocdr->diskNumber ||
        eocdr->diskEntries != eocdr->totalEntries)
    {
        fprintf(stderr, "The input file is a multipart archive - not supported\n");
        return 0; /* FAILED */
    }
#endif
    if (eocdr->commentLen > 0) {
        /* ZIP_EOCDR commentLen is uint16_t (ZIP spec, 2-byte field),
         * so fileCommentLen + 1 cannot overflow size_t */
        eocdr->comment = OPENSSL_zalloc(eocdr->commentLen + 1);
        size = fread(eocdr->comment, 1, eocdr->commentLen, file);
        if (size != eocdr->commentLen) {
            return 0; /* FAILED */
        }
        eocdr->comment[eocdr->commentLen] = 0;
    } else {
        eocdr->comment = NULL;
    }
    return 1; /* OK */
}

/*
 * Read Zip64 end of central directory locator.
 * [out] locator: Zip64 end of central directory locator
 * [in, out] file: FILE pointer to the input file
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
        fprintf(stderr, "The input file is not a valid zip file - could not find zip64 EOCD locator\n");
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
 * [in, out] file: FILE pointer to the input file
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
        fprintf(stderr, "The input file is not a valid zip file - could not find zip64 End of Central Directory record\n");
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
    /* size of the central directory (8 bytes) */
    eocdr->centralDirectorySize = fileGetU64(file);
    /* offset of start of central directory with respect
     * to the starting disk number (8 bytes) */
    eocdr->centralDirectoryOffset = fileGetU64(file);
    /* zip64 extensible data sector (comment) */
    eocdr->commentLen = eocdr->eocdrSize - 44;
    if (eocdr->commentLen > UINT16_MAX) {
        fprintf(stderr, "Corrupted file comment length : 0x%08" PRIX64 "\n", eocdr->commentLen);
        return 0; /* FAILED */
    }
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
        fprintf(stderr, "The input file is a multipart archive - not supported\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

static int get_current_position(BIO *bio, uint64_t *offset)
{
    FILE *file = NULL;
    int64_t pos;

    if (BIO_get_fp(bio, &file) != 1 || file == NULL) {
        fprintf(stderr, "BIO_get_fp() failed\n");
        return 0; /* FAILED */
    }
    pos = ftello(file);
    if (pos < 0) {
        return 0; /* FAILED */
    }
    *offset = (uint64_t)pos;
    return 1; /* OK */
}

static uint64_t fileGetU64(FILE *file)
{
    uint64_t l = fileGetU32(file);
    uint64_t h = fileGetU32(file);
    /* coverity[byte_swapping] */
    return h << 32 | l;
}

/* coverity[ -tainted_data_return ] */
static uint32_t fileGetU32(FILE *file)
{
    uint8_t b[4];
    size_t size = fread(b, 1, 4, file);
    if (size != 4) {
        return 0; /* FAILED */
    }
    return (uint32_t)(b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]);
}

/* coverity[ -tainted_data_return ] */
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
