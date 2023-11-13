/*
 * PE file support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * MS PE/COFF documentation
 * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 */

#include "osslsigncode.h"
#include "helpers.h"

const u_char classid_page_hash[] = {
    0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66,
    0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6
};

typedef struct {
    ASN1_BIT_STRING *flags;
    SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData)

ASN1_SEQUENCE(SpcPeImageData) = {
    ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
    ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)

struct pe_ctx_st {
    uint32_t header_size;
    uint32_t pe32plus;
    uint16_t magic;
    uint32_t pe_checksum;
    uint32_t nrvas;
    uint32_t sigpos;
    uint32_t siglen;
    uint32_t fileend;
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *pe_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static ASN1_OBJECT *pe_spc_image_data_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static int pe_hash_length_get(FILE_FORMAT_CTX *ctx);
static int pe_check_file(FILE_FORMAT_CTX *ctx, int detached);
static u_char *pe_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md);
static int pe_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static int pe_verify_indirect_data(FILE_FORMAT_CTX *ctx, SpcAttributeTypeAndOptionalValue *obj);
static PKCS7 *pe_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static int pe_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *pe_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int pe_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static void pe_update_data_size(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *pe_bio_free(BIO *hash, BIO *outdata);
static void pe_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_pe = {
    .ctx_new = pe_ctx_new,
    .data_blob_get = pe_spc_image_data_get,
    .hash_length_get = pe_hash_length_get,
    .check_file = pe_check_file,
    .digest_calc = pe_digest_calc,
    .verify_digests = pe_verify_digests,
    .verify_indirect_data = pe_verify_indirect_data,
    .pkcs7_extract = pe_pkcs7_extract,
    .remove_pkcs7 = pe_remove_pkcs7,
    .pkcs7_prepare = pe_pkcs7_prepare,
    .append_pkcs7 = pe_append_pkcs7,
    .update_data_size = pe_update_data_size,
    .bio_free = pe_bio_free,
    .ctx_cleanup = pe_ctx_cleanup
};

/* Prototypes */
static PE_CTX *pe_ctx_get(char *indata, uint32_t filesize);
static PKCS7 *pe_pkcs7_get_file(char *indata, PE_CTX *pe_ctx);
static uint32_t pe_calc_checksum(BIO *bio, uint32_t header_size);
static uint32_t pe_calc_realchecksum(FILE_FORMAT_CTX *ctx);
static int pe_modify_header(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int pe_page_hash_get(u_char **ph, int *phlen, int *phtype, SpcAttributeTypeAndOptionalValue *obj);
static u_char *pe_page_hash_calc(int *rphlen, FILE_FORMAT_CTX *ctx, int phtype);
static int pe_verify_page_hash(FILE_FORMAT_CTX *ctx, u_char *ph, int phlen, int phtype);
static SpcLink *pe_page_hash_link_get(FILE_FORMAT_CTX *ctx, int phtype);


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
static FILE_FORMAT_CTX *pe_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
    FILE_FORMAT_CTX *ctx;
    PE_CTX *pe_ctx;
    uint32_t filesize;

    filesize = get_file_size(options->infile);
    if (filesize == 0)
        return NULL; /* FAILED */

    options->indata = map_file(options->infile, filesize);
    if (!options->indata) {
        return NULL; /* FAILED */
    }
    if (memcmp(options->indata, "MZ", 2)) {
        unmap_file(options->infile, filesize);
        return NULL; /* FAILED */
    }
    pe_ctx = pe_ctx_get(options->indata, filesize);
    if (!pe_ctx) {
        unmap_file(options->infile, filesize);
        return NULL; /* FAILED */
    }
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    ctx->format = &file_format_pe;
    ctx->options = options;
    ctx->pe_ctx = pe_ctx;

    /* Push hash on outdata, if hash is NULL the function does nothing */
    BIO_push(hash, outdata);

    if (options->jp >= 0)
        printf("Warning: -jp option is only valid for CAB files\n");
    if (options->add_msi_dse == 1)
        printf("Warning: -add-msi-dse option is only valid for MSI files\n");
    return ctx;
}

/*
 * Allocate and return SpcPeImageData object.
 * [out] p: SpcPeImageData data
 * [out] plen: SpcPeImageData data length
 * [in] ctx: structure holds input and output data
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_PE_IMAGE_DATA_OBJID
 */
static ASN1_OBJECT *pe_spc_image_data_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
    int phtype;
    ASN1_OBJECT *dtype;
    SpcPeImageData *pid = SpcPeImageData_new();

    ASN1_BIT_STRING_set_bit(pid->flags, 0, 1);
    if (ctx->options->pagehash) {
        SpcLink *link;
        phtype = NID_sha1;
        if (EVP_MD_size(ctx->options->md) > EVP_MD_size(EVP_sha1()))
            phtype = NID_sha256;
        link = pe_page_hash_link_get(ctx, phtype);
        if (!link)
            return NULL; /* FAILED */
        pid->file = link;
    } else {
        pid->file = spc_link_obsolete_get();
    }
    *plen = i2d_SpcPeImageData(pid, NULL);
    *p = OPENSSL_malloc((size_t)*plen);
    i2d_SpcPeImageData(pid, p);
    *p -= *plen;
    dtype = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1);
    SpcPeImageData_free(pid);
    return dtype; /* OK */
}

/*
 * [in] ctx: structure holds input and output data
 * [returns] the size of the message digest when passed an EVP_MD structure (the size of the hash)
 */
static int pe_hash_length_get(FILE_FORMAT_CTX *ctx)
{
    return EVP_MD_size(ctx->options->md);
}

/*
 * Print current and calculated PE checksum,
 * check if the signature exists.
 * [in, out] ctx: structure holds input and output data
 * [in] detached: embedded/detached PKCS#7 signature switch
 * [returns] 0 on error or 1 on success
 */
static int pe_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
    uint32_t real_pe_checksum, sum = 0;

    if (!ctx) {
        printf("Init error\n\n");
        return 0; /* FAILED */
    }
    real_pe_checksum = pe_calc_realchecksum(ctx);
    if (ctx->pe_ctx->pe_checksum == real_pe_checksum) {
        printf("PE checksum   : %08X\n\n", real_pe_checksum);
    } else {
        printf("Current PE checksum   : %08X\n", ctx->pe_ctx->pe_checksum);
        printf("Calculated PE checksum: %08X\n", real_pe_checksum);
        printf("Warning: invalid PE checksum\n\n");
    }
    if (detached) {
        printf("Checking the specified catalog file\n\n");
        return 1; /* OK */
    }
    if (ctx->pe_ctx->sigpos == 0 || ctx->pe_ctx->siglen == 0
        || ctx->pe_ctx->sigpos > ctx->pe_ctx->fileend) {
        printf("No signature found\n\n");
        return 0; /* FAILED */
    }
    /*
     * If the sum of the rounded dwLength values does not equal the Size value,
     * then either the attribute certificate table or the Size field is corrupted.
     */
    while (sum < ctx->pe_ctx->siglen) {
        uint32_t len = GET_UINT32_LE(ctx->options->indata + ctx->pe_ctx->sigpos + sum);
        if (ctx->pe_ctx->siglen - len > 8) {
            printf("Corrupted attribute certificate table\n");
            printf("Attribute certificate table size  : %08X\n", ctx->pe_ctx->siglen);
            printf("Attribute certificate entry length: %08X\n\n", len);
            return 0; /* FAILED */
        }
        /* quadword align data */
        len += len % 8 ? 8 - len % 8 : 0;
        sum += len;
    }
    if (sum != ctx->pe_ctx->siglen) {
        printf("Corrupted attribute certificate table\n");
        printf("Attribute certificate table size  : %08X\n", ctx->pe_ctx->siglen);
        printf("Sum of the rounded dwLength values: %08X\n\n", sum);
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/* Compute a message digest value of a signed or unsigned PE file.
 * [in] ctx: structure holds input and output data
 * [in] md: message digest algorithm
 * [returns] pointer to calculated message digest
 */
static u_char *pe_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md)
{
    size_t written;
    uint32_t idx = 0, fileend;
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());

    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return 0;  /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    if (ctx->pe_ctx->sigpos)
        fileend = ctx->pe_ctx->sigpos;
    else
        fileend = ctx->pe_ctx->fileend;

    /* ctx->pe_ctx->header_size + 88 + 4 + 60 + ctx->pe_ctx->pe32plus * 16 + 8 */
    if (!BIO_write_ex(bhash, ctx->options->indata, ctx->pe_ctx->header_size + 88, &written)
        || written != ctx->pe_ctx->header_size + 88) {
        BIO_free_all(bhash);
        return 0; /* FAILED */
    }
    idx += (uint32_t)written + 4;
    if (!BIO_write_ex(bhash, ctx->options->indata + idx,
            60 + ctx->pe_ctx->pe32plus * 16, &written)
        || written != 60 + ctx->pe_ctx->pe32plus * 16) {
        BIO_free_all(bhash);
        return 0; /* FAILED */
    }
    idx += (uint32_t)written + 8;
    if (!bio_hash_data(bhash, ctx->options->indata, idx, fileend)) {
        printf("Unable to calculate digest\n");
        BIO_free_all(bhash);
        return 0;  /* FAILED */
    }
    if (!ctx->pe_ctx->sigpos) {
        /* pad (with 0's) unsigned PE file to 8 byte boundary */
        int len = 8 - ctx->pe_ctx->fileend % 8;
        if (len > 0 && len != 8) {
            char *buf = OPENSSL_malloc(8);
            memset(buf, 0, (size_t)len);
            BIO_write(bhash, buf, len);
            OPENSSL_free(buf);
        }
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    return mdbuf;  /* OK */
}


/*
 * Calculate message digest and page_hash and compare to values retrieved
 * from PKCS#7 signedData.
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int pe_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    int mdtype = -1, phtype = -1, phlen = 0;
    const EVP_MD *md;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    u_char *cmdbuf = NULL;
    u_char *ph = NULL;

    if (is_content_type(p7, SPC_INDIRECT_DATA_OBJID)) {
        ASN1_STRING *content_val = p7->d.sign->contents->d.other->value.sequence;
        const u_char *p = content_val->data;
        SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, content_val->length);
        if (idc) {
            if (!pe_page_hash_get(&ph, &phlen, &phtype, idc->data)) {
                printf("Failed to extract a page hash\n\n");
                SpcIndirectDataContent_free(idc);
                return 0; /* FAILED */
            }
            if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
                mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
                memcpy(mdbuf, idc->messageDigest->digest->data, (size_t)idc->messageDigest->digest->length);
            }
            SpcIndirectDataContent_free(idc);
        }
    }
    if (mdtype == -1) {
        printf("Failed to extract current message digest\n\n");
        OPENSSL_free(ph);
        return 0; /* FAILED */
    }
    md = EVP_get_digestbynid(mdtype);
    cmdbuf = pe_digest_calc(ctx, md);
    if (!cmdbuf) {
        printf("Failed to calculate message digest\n\n");
        OPENSSL_free(ph);
        return 0; /* FAILED */
    }
    if (!compare_digests(mdbuf, cmdbuf, mdtype)) {
        printf("Signature verification: failed\n\n");
        OPENSSL_free(ph);
        OPENSSL_free(cmdbuf);
        return 0; /* FAILED */
    }
    if (!pe_verify_page_hash(ctx, ph, phlen, phtype)) {
        printf("Signature verification: failed\n\n");
        OPENSSL_free(ph);
        OPENSSL_free(cmdbuf);
        return 0; /* FAILED */
    }
    OPENSSL_free(ph);
    OPENSSL_free(cmdbuf);
    return 1; /* OK */
}

/*
 * Verify page hash.
 * [in] ctx: structure holds input and output data
 * [in] obj: SPC_INDIRECT_DATA OID: 1.3.6.1.4.1.311.2.1.4 containing page hash
 * [returns] 0 on error or 1 on success
 */
static int pe_verify_indirect_data(FILE_FORMAT_CTX *ctx, SpcAttributeTypeAndOptionalValue *obj)
{
    int phtype = -1, phlen = 0;
    u_char *ph = NULL;

    if (!pe_page_hash_get(&ph, &phlen, &phtype, obj)) {
        printf("Failed to extract a page hash\n\n");
        return 0; /* FAILED */
    }
    if (!pe_verify_page_hash(ctx, ph, phlen, phtype)) {
        printf("Page hash verification: failed\n\n");
        OPENSSL_free(ph);
        return 0; /* FAILED */
    }
    OPENSSL_free(ph);
    return 1; /* OK */
}

/*
 * Extract existing signature in DER format.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *pe_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
    if (ctx->pe_ctx->sigpos == 0 || ctx->pe_ctx->siglen == 0
        || ctx->pe_ctx->sigpos > ctx->pe_ctx->fileend) {
        return NULL; /* FAILED */
    }
    return pe_pkcs7_get_file(ctx->options->indata, ctx->pe_ctx);
}

/*
 * Remove existing signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int pe_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (ctx->pe_ctx->sigpos == 0) {
        printf("PE file does not have any signature\n");
        return 1; /* FAILED */
    }
    /* Strip current signature */
    ctx->pe_ctx->fileend = ctx->pe_ctx->sigpos;
    if (!pe_modify_header(ctx, hash, outdata)) {
        printf("Unable to modify file header\n");
        return 1; /* FAILED */
    }
    return 0; /* OK */
}

/*
 * Obtain an existing signature or create a new one.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *pe_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    PKCS7 *cursig = NULL, *p7 = NULL;

    /* Obtain a current signature from previously-signed file */
    if ((ctx->options->cmd == CMD_SIGN && ctx->options->nest)
        || (ctx->options->cmd == CMD_ATTACH && ctx->options->nest)
        || ctx->options->cmd == CMD_ADD) {
        cursig = pe_pkcs7_get_file(ctx->options->indata, ctx->pe_ctx);
        if (!cursig) {
            printf("Unable to extract existing signature\n");
            return NULL; /* FAILED */
        }
        if (ctx->options->cmd == CMD_ADD)
            p7 = cursig;
    }
    if (ctx->pe_ctx->sigpos > 0) {
        /* Strip current signature */
        ctx->pe_ctx->fileend = ctx->pe_ctx->sigpos;
    }
    if (!pe_modify_header(ctx, hash, outdata)) {
        printf("Unable to modify file header\n");
        return NULL; /* FAILED */
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
        if (!add_indirect_data_object(p7)) {
            printf("Adding SPC_INDIRECT_DATA_OBJID failed\n");
            PKCS7_free(p7);
            return NULL; /* FAILED */
        }
        if (!sign_spc_indirect_data_content(p7, hash, ctx)) {
            printf("Failed to set signed content\n");
            return NULL; /* FAILED */
        }
    }
    if (ctx->options->nest)
        ctx->options->prevsig = cursig;
    return p7;
}

/*
 * Append signature to the outfile.
 * [in, out] ctx: structure holds input and output data (unused)
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int pe_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    u_char *p = NULL;
    int len;       /* signature length */
    int padlen;    /* signature padding length */
    u_char buf[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* squash the unused parameter warning */
    (void)ctx;

    if (((len = i2d_PKCS7(p7, NULL)) <= 0)
        || (p = OPENSSL_malloc((size_t)len)) == NULL) {
        printf("i2d_PKCS memory allocation failed: %d\n", len);
        return 1; /* FAILED */
    }
    i2d_PKCS7(p7, &p);
    p -= len;
    padlen = len % 8 ? 8 - len % 8 : 0;
    PUT_UINT32_LE(len + 8 + padlen, buf);
    PUT_UINT16_LE(WIN_CERT_REVISION_2_0, buf + 4);
    PUT_UINT16_LE(WIN_CERT_TYPE_PKCS_SIGNED_DATA, buf + 6);
    BIO_write(outdata, buf, 8);
    BIO_write(outdata, p, len);
    /* pad (with 0's) asn1 blob to 8 byte boundary */
    if (padlen > 0) {
        memset(p, 0, (size_t)padlen);
        BIO_write(outdata, p, padlen);
    }
    OPENSSL_free(p);
    return 0; /* OK */
}

/*
 * Update signature position and size, write back new checksum.
 * [in, out] ctx: structure holds input and output data
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] none
 */
static void pe_update_data_size(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    uint32_t checksum;
    u_char buf[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if (p7) {
        int len = i2d_PKCS7(p7, NULL);
        int padlen = len % 8 ? 8 - len % 8 : 0;

        /* Update signature position and size */
        (void)BIO_seek(outdata,
            ctx->pe_ctx->header_size + 152 + ctx->pe_ctx->pe32plus * 16);
        /* Previous file end = signature table start */
        PUT_UINT32_LE(ctx->pe_ctx->fileend, buf);
        BIO_write(outdata, buf, 4);
        PUT_UINT32_LE(len + 8 + padlen, buf);
        BIO_write(outdata, buf, 4);
    } /* else CMD_REMOVE */

    /* write back checksum */
    checksum = pe_calc_checksum(outdata, ctx->pe_ctx->header_size);
    (void)BIO_seek(outdata, ctx->pe_ctx->header_size + 88);
    PUT_UINT32_LE(checksum, buf);
    BIO_write(outdata, buf, 4);
}

/*
 * Free up an entire message digest BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO (unused)
 * [returns] none
 */
static BIO *pe_bio_free(BIO *hash, BIO *outdata)
{
    /* squash the unused parameter warning */
    (void)outdata;

    BIO_free_all(hash);
    return NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and PE format specific structure,
 * unmap indata file.
 * [out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] none
 */
static void pe_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (outdata) {
        BIO_free_all(hash);
    }
    unmap_file(ctx->options->indata, ctx->pe_ctx->fileend);
    OPENSSL_free(ctx->pe_ctx);
    OPENSSL_free(ctx);
}

/*
 * PE helper functions
 */

/*
 * Verify mapped PE file and create PE format specific structure.
 * [in] indata: mapped PE file
 * [in] filesize: size of PE file
 * [returns] pointer to PE format specific structure
 */
static PE_CTX *pe_ctx_get(char *indata, uint32_t filesize)
{
    PE_CTX *pe_ctx;
    uint32_t header_size, pe32plus, pe_checksum, nrvas, sigpos, siglen;
    uint16_t magic;

    if (filesize < 64) {
        printf("Corrupt DOS file - too short\n");
        return NULL; /* FAILED */
    }
    /* SizeOfHeaders field specifies the combined size of an MS-DOS stub, PE header,
     * and section headers rounded up to a multiple of FileAlignment.
     * SizeOfHeaders must be < filesize and cannot be < 0x0000002C (44) in Windows 7
     * because of a bug when checking section names for compatibility purposes */
    header_size = GET_UINT32_LE(indata + 60);
    if (header_size < 44 || header_size > filesize) {
        printf("Unexpected SizeOfHeaders field: 0x%08X\n", header_size);
        return NULL; /* FAILED */
    }
    if (filesize < header_size + 176) {
        printf("Corrupt PE file - too short\n");
        return NULL; /* FAILED */
    }
    if (memcmp(indata + header_size, "PE\0\0", 4)) {
        printf("Unrecognized DOS file type\n");
        return NULL; /* FAILED */
    }
    /* Magic field identifies the state of the image file. The most common number is
     * 0x10B, which identifies it as a normal executable file,
     * 0x20B identifies it as a PE32+ executable,
     * 0x107 identifies it as a ROM image (not supported) */
    magic = GET_UINT16_LE(indata + header_size + 24);
    if (magic == 0x20b) {
        pe32plus = 1;
    } else if (magic == 0x10b) {
        pe32plus = 0;
    } else {
        printf("Corrupt PE file - found unknown magic %04X\n", magic);
        return NULL; /* FAILED */
    }
    /* The image file checksum */
    pe_checksum = GET_UINT32_LE(indata + header_size + 88);
    /* NumberOfRvaAndSizes field specifies the number of data-directory entries
     * in the remainder of the optional header. Each describes a location and size. */
    nrvas = GET_UINT32_LE(indata + header_size + 116 + pe32plus * 16);
    if (nrvas < 5) {
        printf("Can not handle PE files without certificate table resource\n");
        return NULL; /* FAILED */
    }
    /* Certificate Table field specifies the attribute certificate table address (4 bytes) and size (4 bytes) */
    sigpos = GET_UINT32_LE(indata + header_size + 152 + pe32plus * 16);
    siglen = GET_UINT32_LE(indata + header_size + 152 + pe32plus * 16 + 4);
    /* Since fix for MS Bulletin MS12-024 we can really assume
       that signature should be last part of file */
    if ((sigpos > 0 && sigpos < filesize && sigpos + siglen != filesize)
        || (sigpos >= filesize)) {
        printf("Corrupt PE file - current signature not at the end of the file\n");
        return NULL; /* FAILED */
    }
    if ((sigpos > 0 && siglen == 0) || (sigpos == 0 && siglen > 0)) {
        printf("Corrupt signature\n");
        return NULL; /* FAILED */
    }
    pe_ctx = OPENSSL_zalloc(sizeof(PE_CTX));
    pe_ctx->header_size = header_size;
    pe_ctx->pe32plus = pe32plus;
    pe_ctx->magic = magic;
    pe_ctx->pe_checksum = pe_checksum;
    pe_ctx->nrvas = nrvas;
    pe_ctx->sigpos = sigpos;
    pe_ctx->siglen = siglen;
    pe_ctx->fileend = filesize;
    return pe_ctx; /* OK */
}

/*
 * Retrieve and verify a decoded PKCS#7 structure corresponding
 * to the existing signature of the PE file.
 * [in] indata: mapped PE file
 * [in] pe_ctx: PE format specific structures
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *pe_pkcs7_get_file(char *indata, PE_CTX *pe_ctx)
{
    uint32_t pos = 0;

    if (pe_ctx->siglen == 0 || pe_ctx->siglen > pe_ctx->fileend) {
        printf("Corrupted signature length: 0x%08X\n", pe_ctx->siglen);
        return NULL; /* FAILED */
    }
    while (pos < pe_ctx->siglen) {
        uint32_t len = GET_UINT32_LE(indata + pe_ctx->sigpos + pos);
        uint16_t certrev = GET_UINT16_LE(indata + pe_ctx->sigpos + pos + 4);
        uint16_t certtype = GET_UINT16_LE(indata + pe_ctx->sigpos + pos + 6);
        if (certrev == WIN_CERT_REVISION_2_0 && certtype == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
            /* skip 8 bytes from the attribute certificate table */
            const u_char *blob = (u_char *)indata + pe_ctx->sigpos + pos + 8;
            return d2i_PKCS7(NULL, &blob, len - 8);
        }
        /* quadword align data */
        len += len % 8 ? 8 - len % 8 : 0;
        pos += len;
    }
    return NULL; /* FAILED */
}

/*
 * Calculate checksum.
 * A signed PE file is padded (with 0's) to 8 byte boundary,
 * ignore any last odd byte in an unsigned file.
 * [in] outdata: outdata file BIO
 * [in] header_size: PE header size
 * [returns] checksum
 */
static uint32_t pe_calc_checksum(BIO *outdata, uint32_t header_size)
{
    uint32_t checkSum = 0, offset = 0;
    int nread;
    unsigned short *buf = OPENSSL_malloc(SIZE_64K);

    /* recalculate the checksum */
    (void)BIO_seek(outdata, 0);
    while ((nread = BIO_read(outdata, buf, SIZE_64K)) > 0) {
        unsigned short val;
        int i;
        for (i = 0; i < nread / 2; i++) {
            val = LE_UINT16(buf[i]);
            if (offset == header_size + 88 || offset == header_size + 90)
                val = 0;
            checkSum += val;
            checkSum = LOWORD(LOWORD(checkSum) + HIWORD(checkSum));
            offset += 2;
        }
    }
    OPENSSL_free(buf);
    checkSum = LOWORD(LOWORD(checkSum) + HIWORD(checkSum));
    checkSum += offset;
    return checkSum;
}

/*
 * Compute a checkSum value of the signed or unsigned PE file.
 * [in] ctx: structure holds input and output data
 * [returns] checksum
 */
static uint32_t pe_calc_realchecksum(FILE_FORMAT_CTX *ctx)
{
    uint32_t n = 0, checkSum = 0, offset = 0;
    BIO *bio = BIO_new(BIO_s_mem());
    unsigned short *buf = OPENSSL_malloc(SIZE_64K);

    /* calculate the checkSum */
    while (n < ctx->pe_ctx->fileend) {
        size_t i, written, nread;
        size_t left = ctx->pe_ctx->fileend - n;
        unsigned short val;
        if (left > SIZE_64K)
            left = SIZE_64K;
        if (!BIO_write_ex(bio, ctx->options->indata + n, left, &written))
            goto err; /* FAILED */
        (void)BIO_seek(bio, 0);
        n += (uint32_t)written;
        if (!BIO_read_ex(bio, buf, written, &nread))
            goto err; /* FAILED */
        for (i = 0; i < nread / 2; i++) {
            val = LE_UINT16(buf[i]);
            if (offset == ctx->pe_ctx->header_size + 88
                || offset == ctx->pe_ctx->header_size + 90) {
                val = 0;
            }
            checkSum += val;
            checkSum = LOWORD(LOWORD(checkSum) + HIWORD(checkSum));
            offset += 2;
        }
    }
    checkSum = LOWORD(LOWORD(checkSum) + HIWORD(checkSum));
    checkSum += offset;
err:
    OPENSSL_free(buf);
    BIO_free(bio);
    return checkSum;
}

/*
 * Modify PE header.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int pe_modify_header(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    size_t i, len, written;
    char *buf;

    i = len = ctx->pe_ctx->header_size + 88;
    if (!BIO_write_ex(hash, ctx->options->indata, len, &written)
        || written != len) {
        return 0; /* FAILED */
    }
    buf = OPENSSL_malloc(SIZE_64K);
    memset(buf, 0, 4);
    BIO_write(outdata, buf, 4); /* zero out checksum */
    i += 4;
    len = 60 + ctx->pe_ctx->pe32plus * 16;
    if (!BIO_write_ex(hash, ctx->options->indata + i, len, &written)
        || written != len) {
        OPENSSL_free(buf);
        return 0; /* FAILED */
    }
    i += 60 + ctx->pe_ctx->pe32plus * 16;
    memset(buf, 0, 8);
    BIO_write(outdata, buf, 8); /* zero out sigtable offset + pos */
    i += 8;
    len = ctx->pe_ctx->fileend - i;
    while (len > 0) {
        if (!BIO_write_ex(hash, ctx->options->indata + i, len, &written)) {
            OPENSSL_free(buf);
            return 0; /* FAILED */
        }
        len -= written;
        i += written;
    }
    /* pad (with 0's) pe file to 8 byte boundary */
    len = 8 - ctx->pe_ctx->fileend % 8;
    if (len != 8) {
        memset(buf, 0, len);
        if (!BIO_write_ex(hash, buf, len, &written) || written != len) {
            OPENSSL_free(buf);
            return 0; /* FAILED */
        }
        ctx->pe_ctx->fileend += (uint32_t)len;
    }
    OPENSSL_free(buf);
    return 1; /* OK */
}

/*
 * Page hash support
 */

/*
 * Retrieve a page hash from SPC_INDIRECT_DATA structure.
 * [out] ph: page hash
 * [out] phlen: page hash length
 * [out] phtype: NID_sha1 or NID_sha256
 * [in] obj: SPC_INDIRECT_DATA OID: 1.3.6.1.4.1.311.2.1.4 containing page hash
 * [returns] 0 on error or 1 on success
 */
static int pe_page_hash_get(u_char **ph, int *phlen, int *phtype, SpcAttributeTypeAndOptionalValue *obj)
{
    const u_char *blob;
    SpcPeImageData *id;
    SpcSerializedObject *so;
    int l, l2;
    char buf[128];

    if (!obj || !obj->value)
        return 0; /* FAILED */
    blob = obj->value->value.sequence->data;
    id = d2i_SpcPeImageData(NULL, &blob, obj->value->value.sequence->length);
    if (!id) {
        return 0; /* FAILED */
    }
    if (!id->file) {
        SpcPeImageData_free(id);
        return 0; /* FAILED */
    }
    if (id->file->type != 1) {
        SpcPeImageData_free(id);
        return 1; /* OK - This is not SpcSerializedObject structure that contains page hashes */
    }
    so = id->file->value.moniker;
    if (so->classId->length != sizeof classid_page_hash ||
        memcmp(so->classId->data, classid_page_hash, sizeof classid_page_hash)) {
        SpcPeImageData_free(id);
        return 0; /* FAILED */
    }
    /* skip ASN.1 SET hdr */
    l = asn1_simple_hdr_len(so->serializedData->data, so->serializedData->length);
    blob = so->serializedData->data + l;
    obj = d2i_SpcAttributeTypeAndOptionalValue(NULL, &blob, so->serializedData->length - l);
    SpcPeImageData_free(id);
    if (!obj)
        return 0; /* FAILED */

    *phtype = 0;
    buf[0] = 0x00;
    OBJ_obj2txt(buf, sizeof buf, obj->type, 1);
    if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V1)) {
        *phtype = NID_sha1;
    } else if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V2)) {
        *phtype = NID_sha256;
    } else {
        SpcAttributeTypeAndOptionalValue_free(obj);
        return 0; /* FAILED */
    }
    /* Skip ASN.1 SET hdr */
    l2 = asn1_simple_hdr_len(obj->value->value.sequence->data, obj->value->value.sequence->length);
    /* Skip ASN.1 OCTET STRING hdr */
    l = asn1_simple_hdr_len(obj->value->value.sequence->data + l2, obj->value->value.sequence->length - l2);
    l += l2;
    *phlen = obj->value->value.sequence->length - l;
    *ph = OPENSSL_malloc((size_t)*phlen);
    memcpy(*ph, obj->value->value.sequence->data + l, (size_t)*phlen);
    SpcAttributeTypeAndOptionalValue_free(obj);
    return 1; /* OK */
}

/*
 * Calculate page hash for the PE file.
 * [out] rphlen: page hash length
 * [in] ctx: structure holds input and output data
 * [in] phtype: NID_sha1 or NID_sha256
 * [returns] pointer to calculated page hash
 */
static u_char *pe_page_hash_calc(int *rphlen, FILE_FORMAT_CTX *ctx, int phtype)
{
    uint16_t nsections, opthdr_size;
    uint32_t alignment, pagesize, hdrsize;
    uint32_t rs, ro, l, lastpos = 0;
    int pphlen, phlen, i, pi = 1;
    size_t written;
    u_char *res, *zeroes;
    char *sections;
    const EVP_MD *md = EVP_get_digestbynid(phtype);
    BIO *bhash;

    /* NumberOfSections indicates the size of the section table,
     * which immediately follows the headers, can be up to 65535 under Vista and later */
    nsections = GET_UINT16_LE(ctx->options->indata + ctx->pe_ctx->header_size + 6);
    if (nsections == 0) {
        printf("Corrupted number of sections: 0x%08X\n", nsections);
        return NULL; /* FAILED */
    }
    /* FileAlignment is the alignment factor (in bytes) that is used to align
     * the raw data of sections in the image file. The value should be a power
     * of 2 between 512 and 64 K, inclusive. The default is 512. */
    alignment = GET_UINT32_LE(ctx->options->indata + ctx->pe_ctx->header_size + 60);
    if (alignment < 512 || alignment > UINT16_MAX) {
        printf("Corrupted file alignment factor: 0x%08X\n", alignment);
        return NULL; /* FAILED */
    }
    /* SectionAlignment is the alignment (in bytes) of sections when they are
     * loaded into memory. It must be greater than or equal to FileAlignment.
     * The default is the page size for the architecture.
     * The large page size is at most 4 MB.
     * https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200 */
    pagesize = GET_UINT32_LE(ctx->options->indata + ctx->pe_ctx->header_size + 56);
    if (pagesize == 0 || pagesize < alignment || pagesize > 4194304) {
        printf("Corrupted page size: 0x%08X\n", pagesize);
        return NULL; /* FAILED */
    }
    /* SizeOfHeaders is the combined size of an MS-DOS stub, PE header,
     * and section headers rounded up to a multiple of FileAlignment. */
    hdrsize = GET_UINT32_LE(ctx->options->indata + ctx->pe_ctx->header_size + 84);
    if (hdrsize < ctx->pe_ctx->header_size || hdrsize > UINT32_MAX) {
        printf("Corrupted headers size: 0x%08X\n", hdrsize);
        return NULL; /* FAILED */
    }
    /* SizeOfOptionalHeader is the size of the optional header, which is
     * required for executable files, but for object files should be zero,
     * and can't be bigger than the file */
    opthdr_size = GET_UINT16_LE(ctx->options->indata + ctx->pe_ctx->header_size + 20);
    if (opthdr_size == 0 || opthdr_size > ctx->pe_ctx->fileend) {
        printf("Corrupted optional header size: 0x%08X\n", opthdr_size);
        return NULL; /* FAILED */
    }
    pphlen = 4 + EVP_MD_size(md);
    phlen = pphlen * (3 + (int)nsections + (int)(ctx->pe_ctx->fileend / pagesize));

    bhash = BIO_new(BIO_f_md());
    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return NULL;  /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    if (!BIO_write_ex(bhash, ctx->options->indata, ctx->pe_ctx->header_size + 88, &written)
        || written != ctx->pe_ctx->header_size + 88) {
        BIO_free_all(bhash);
        return NULL;  /* FAILED */
    }
    if (!BIO_write_ex(bhash, ctx->options->indata + ctx->pe_ctx->header_size + 92,
        60 + ctx->pe_ctx->pe32plus*16, &written)
        || written != 60 + ctx->pe_ctx->pe32plus*16) {
        BIO_free_all(bhash);
        return NULL;  /* FAILED */
    }
    if (!BIO_write_ex(bhash,
        ctx->options->indata + ctx->pe_ctx->header_size + 160 + ctx->pe_ctx->pe32plus*16,
        hdrsize - (ctx->pe_ctx->header_size + 160 + ctx->pe_ctx->pe32plus*16), &written)
        || written != hdrsize - (ctx->pe_ctx->header_size + 160 + ctx->pe_ctx->pe32plus*16)) {
        BIO_free_all(bhash);
        return NULL;  /* FAILED */
    }
    zeroes = OPENSSL_zalloc((size_t)pagesize);
    if (!BIO_write_ex(bhash, zeroes, pagesize - hdrsize, &written)
        || written != pagesize - hdrsize) {
        BIO_free_all(bhash);
        OPENSSL_free(zeroes);
        return NULL;  /* FAILED */
    }
    res = OPENSSL_malloc((size_t)phlen);
    memset(res, 0, 4);
    BIO_gets(bhash, (char*)res + 4, EVP_MD_size(md));
    BIO_free_all(bhash);
    sections = ctx->options->indata + ctx->pe_ctx->header_size + 24 + opthdr_size;
    for (i=0; i<nsections; i++) {
        /* Resource Table address and size */
        rs = GET_UINT32_LE(sections + 16);
        ro = GET_UINT32_LE(sections + 20);
        if (rs == 0 || rs >= UINT32_MAX) {
            sections += 40;
            continue;
        }
        for (l=0; l<rs; l+=pagesize, pi++) {
            PUT_UINT32_LE(ro + l, res + pi*pphlen);
            bhash = BIO_new(BIO_f_md());
            if (!BIO_set_md(bhash, md)) {
                printf("Unable to set the message digest of BIO\n");
                BIO_free_all(bhash);
                OPENSSL_free(zeroes);
                OPENSSL_free(res);
                return NULL;  /* FAILED */
            }
            BIO_push(bhash, BIO_new(BIO_s_null()));
            if (rs - l < pagesize) {
                if (!BIO_write_ex(bhash, ctx->options->indata + ro + l, rs - l, &written)
                    || written != rs - l) {
                    BIO_free_all(bhash);
                    OPENSSL_free(zeroes);
                    OPENSSL_free(res);
                    return NULL;  /* FAILED */
                }
                if (!BIO_write_ex(bhash, zeroes, pagesize - (rs - l), &written)
                    || written != pagesize - (rs - l)) {
                    BIO_free_all(bhash);
                    OPENSSL_free(zeroes);
                    OPENSSL_free(res);
                    return NULL;  /* FAILED */
                }
            } else {
                if (!BIO_write_ex(bhash, ctx->options->indata + ro + l, pagesize, &written)
                    || written != pagesize) {
                    BIO_free_all(bhash);
                    OPENSSL_free(zeroes);
                    OPENSSL_free(res);
                    return NULL;  /* FAILED */
                }
            }
            BIO_gets(bhash, (char*)res + pi*pphlen + 4, EVP_MD_size(md));
            BIO_free_all(bhash);
        }
        lastpos = ro + rs;
        sections += 40;
    }
    PUT_UINT32_LE(lastpos, res + pi*pphlen);
    memset(res + pi*pphlen + 4, 0, (size_t)EVP_MD_size(md));
    pi++;
    OPENSSL_free(zeroes);
    *rphlen = pi*pphlen;
    return res;
}

/*
 * Calculate page hash for the PE file, compare with the given value and print values.
 * [in] ctx: structure holds input and output data
 * [in] ph: page hash
 * [in] phlen: page hash length
 * [in] phtype: NID_sha1 or NID_sha256
 * [returns] 0 on error or 1 on success
 */
static int pe_verify_page_hash(FILE_FORMAT_CTX *ctx, u_char *ph, int phlen, int phtype)
{
    int mdok, cphlen = 0;
    u_char *cph;

    if (!ph)
        return 1; /* OK */
    cph = pe_page_hash_calc(&cphlen, ctx, phtype);
    mdok = (phlen == cphlen) && !memcmp(ph, cph, (size_t)phlen);
    printf("Page hash algorithm  : %s\n", OBJ_nid2sn(phtype));
    if (ctx->options->verbose) {
        print_hash("Page hash            ", "", ph, phlen);
        print_hash("Calculated page hash ", mdok ? "\n" : "... MISMATCH!!!\n", cph, cphlen);
    } else {
        print_hash("Page hash            ", "...", ph, (phlen < 32) ? phlen : 32);
        print_hash("Calculated page hash ", mdok ? "...\n" : "... MISMATCH!!!\n", cph, (cphlen < 32) ? cphlen : 32);
    }
    OPENSSL_free(cph);
    return mdok;
}

/*
 * Create a new SpcLink structure.
 * [in] ctx: structure holds input and output data
 * [in] phtype: NID_sha1 or NID_sha256
 * [returns] pointer to SpcLink structure
 */
static SpcLink *pe_page_hash_link_get(FILE_FORMAT_CTX *ctx, int phtype)
{
    u_char *ph, *p, *tmp;
    int l, phlen;
    ASN1_TYPE *tostr;
    SpcAttributeTypeAndOptionalValue *aval;
    ASN1_TYPE *taval;
    SpcSerializedObject *so;
    SpcLink *link;
    STACK_OF(ASN1_TYPE) *oset, *aset;

    ph = pe_page_hash_calc(&phlen, ctx, phtype);
    if (!ph) {
        printf("Failed to calculate page hash\n");
        return NULL; /* FAILED */
    }
    if (ctx->options->verbose)
        print_hash("Calculated page hash            ", "", ph, phlen);
    else
        print_hash("Calculated page hash            ", "...", ph, (phlen < 32) ? phlen : 32);

    tostr = ASN1_TYPE_new();
    tostr->type = V_ASN1_OCTET_STRING;
    tostr->value.octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(tostr->value.octet_string, ph, phlen);
    OPENSSL_free(ph);

    oset = sk_ASN1_TYPE_new_null();
    sk_ASN1_TYPE_push(oset, tostr);
    l = i2d_ASN1_SET_ANY(oset, NULL);
    tmp = p = OPENSSL_malloc((size_t)l);
    i2d_ASN1_SET_ANY(oset, &tmp);
    ASN1_TYPE_free(tostr);
    sk_ASN1_TYPE_free(oset);

    aval = SpcAttributeTypeAndOptionalValue_new();
    aval->type = OBJ_txt2obj((phtype == NID_sha1) ?
            SPC_PE_IMAGE_PAGE_HASHES_V1 : SPC_PE_IMAGE_PAGE_HASHES_V2, 1);
    aval->value = ASN1_TYPE_new();
    aval->value->type = V_ASN1_SET;
    aval->value->value.set = ASN1_STRING_new();
    ASN1_STRING_set(aval->value->value.set, p, l);
    OPENSSL_free(p);
    l = i2d_SpcAttributeTypeAndOptionalValue(aval, NULL);
    tmp = p = OPENSSL_malloc((size_t)l);
    i2d_SpcAttributeTypeAndOptionalValue(aval, &tmp);
    SpcAttributeTypeAndOptionalValue_free(aval);

    taval = ASN1_TYPE_new();
    taval->type = V_ASN1_SEQUENCE;
    taval->value.sequence = ASN1_STRING_new();
    ASN1_STRING_set(taval->value.sequence, p, l);
    OPENSSL_free(p);

    aset = sk_ASN1_TYPE_new_null();
    sk_ASN1_TYPE_push(aset, taval);
    l = i2d_ASN1_SET_ANY(aset, NULL);
    tmp = p = OPENSSL_malloc((size_t)l);
    l = i2d_ASN1_SET_ANY(aset, &tmp);
    ASN1_TYPE_free(taval);
    sk_ASN1_TYPE_free(aset);

    so = SpcSerializedObject_new();
    ASN1_OCTET_STRING_set(so->classId, classid_page_hash, sizeof classid_page_hash);
    ASN1_OCTET_STRING_set(so->serializedData, p, l);
    OPENSSL_free(p);

    link = SpcLink_new();
    link->type = 1;
    link->value.moniker = so;
    return link;
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: nil
End:

  vim: set ts=4 expandtab:
*/
