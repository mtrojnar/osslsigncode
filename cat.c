/*
 * CAT file support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * Catalog files are a bit odd, in that they are only a PKCS7 blob.
 */

#include "osslsigncode.h"
#include "helpers.h"

const u_char pkcs7_signed_data[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x07, 0x02,
};

struct cat_ctx_st {
    uint32_t sigpos;
    uint32_t siglen;
    uint32_t fileend;
    PKCS7 *p7;
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *cat_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static int cat_check_file(FILE_FORMAT_CTX *ctx, int detached);
static int cat_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *cat_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static PKCS7 *cat_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int cat_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *cat_bio_free(BIO *hash, BIO *outdata);
static void cat_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_cat = {
    .ctx_new = cat_ctx_new,
    .check_file = cat_check_file,
    .verify_digests = cat_verify_digests,
    .pkcs7_extract = cat_pkcs7_extract,
    .pkcs7_prepare = cat_pkcs7_prepare,
    .append_pkcs7 = cat_append_pkcs7,
    .bio_free = cat_bio_free,
    .ctx_cleanup = cat_ctx_cleanup,
};

/* Prototypes */
static CAT_CTX *cat_ctx_get(char *indata, uint32_t filesize);
static int cat_add_ms_ctl_object(PKCS7 *p7);
static int cat_sign_ms_ctl_content(PKCS7 *p7, PKCS7 *contents);

/*
 * FILE_FORMAT method definitions
 */

/*
 * Allocate and return a CAT file format context.
 * [in, out] options: structure holds the input data
 * [out] hash: message digest BIO (unused)
 * [in] outdata: outdata file BIO (unused)
 * [returns] pointer to CAT file format context
 */
static FILE_FORMAT_CTX *cat_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
    FILE_FORMAT_CTX *ctx;
    CAT_CTX *cat_ctx;
    uint32_t filesize;

    if (options->cmd == CMD_REMOVE || options->cmd==CMD_ATTACH) {
        printf("Unsupported command\n");
        return NULL; /* FAILED */
    }
    if (options->cmd == CMD_VERIFY) {
        printf("Warning: Use -catalog option to verify that a file, listed in catalog file, is signed\n\n");
    }
    filesize = get_file_size(options->infile);
    if (filesize == 0)
        return NULL; /* FAILED */

    options->indata = map_file(options->infile, filesize);
    if (!options->indata) {
        return NULL; /* FAILED */
    }
    /* the maximum size of a supported cat file is (2^24 -1) bytes */
    if (memcmp(options->indata + ((GET_UINT8_LE(options->indata+1) == 0x82) ? 4 : 5),
            pkcs7_signed_data, sizeof pkcs7_signed_data)) {
        unmap_file(options->infile, filesize);
        return NULL; /* FAILED */
    }
    cat_ctx = cat_ctx_get(options->indata, filesize);
    if (!cat_ctx) {
        unmap_file(options->infile, filesize);
        return NULL; /* FAILED */
    }
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    ctx->format = &file_format_cat;
    ctx->options = options;
    ctx->cat_ctx = cat_ctx;

    /* Push hash on outdata, if hash is NULL the function does nothing */
    BIO_push(hash, outdata);

    if (options->nest)
        /* I've not tried using set_nested_signature as signtool won't do this */
        printf("Warning: CAT files do not support nesting (multiple signature)\n");
    if (options->jp >= 0)
        printf("Warning: -jp option is only valid for CAB files\n");
    if (options->pagehash == 1)
        printf("Warning: -ph option is only valid for PE files\n");
    if (options->add_msi_dse == 1)
        printf("Warning: -add-msi-dse option is only valid for MSI files\n");
    return ctx;
}

static int cat_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;

    if (!ctx) {
        printf("Init error\n\n");
        return 0; /* FAILED */
    }
    if (detached) {
        printf("CAT format does not support detached PKCS#7 signature\n\n");
        return 0; /* FAILED */
    }
    signer_info = PKCS7_get_signer_info(ctx->cat_ctx->p7);
    if (!signer_info) {
        printf("Failed catalog file\n\n");
        return 0; /* FAILED */
    }
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si) {
        printf("No signature found\n\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * ContentInfo value is the inner content of pkcs7-signedData.
 * An extra verification is not necessary when a content type data
 * is the inner content of the signed-data type.
 */
static int cat_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    /* squash unused parameter warnings */
    (void)ctx;
    (void)p7;
    return 1; /* OK */
}

/*
 * Extract existing signature in DER format.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *cat_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
    return PKCS7_dup(ctx->cat_ctx->p7);
}

/*
 * Obtain an existing signature or create a new one.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [out] outdata: outdata file BIO (unused)
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *cat_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    PKCS7 *p7 = NULL;

    /* squash unused parameter warnings */
    (void)outdata;
    (void)hash;

    /* Obtain an existing signature */
    if (ctx->options->cmd == CMD_ADD || ctx->options->cmd == CMD_ATTACH) {
        p7 = PKCS7_dup(ctx->cat_ctx->p7);
    } else if (ctx->options->cmd == CMD_SIGN) {
        /* Create a new signature */
        p7 = pkcs7_create(ctx);
        if (!p7) {
            printf("Creating a new signature failed\n");
            return NULL; /* FAILED */
        }
        if (!cat_add_ms_ctl_object(p7)) {
            printf("Adding MS_CTL_OBJID failed\n");
            PKCS7_free(p7);
            return NULL; /* FAILED */
        }
        if (!cat_sign_ms_ctl_content(p7, ctx->cat_ctx->p7->d.sign->contents)) {
            printf("Failed to set signed content\n");
            PKCS7_free(p7);
            return 0; /* FAILED */
        }
   }
    return p7; /* OK */
}

/*
 * Append signature to the outfile.
 * [in, out] ctx: structure holds input and output data (unused)
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int cat_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    u_char *p = NULL;
    int len; /* signature length */

    /* squash the unused parameter warning */
    (void)ctx;

    if (((len = i2d_PKCS7(p7, NULL)) <= 0)
        || (p = OPENSSL_malloc((size_t)len)) == NULL) {
        printf("i2d_PKCS memory allocation failed: %d\n", len);
        return 1; /* FAILED */
    }
    i2d_PKCS7(p7, &p);
    p -= len;
    i2d_PKCS7_bio(outdata, p7);
    OPENSSL_free(p);
    return 0; /* OK */
}

/*
 * Free up an entire message digest BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO (unused)
 * [returns] none
 */
static BIO *cat_bio_free(BIO *hash, BIO *outdata)
{
    /* squash the unused parameter warning */
    (void)outdata;

    BIO_free_all(hash);
    return NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and CAT format specific structure,
 * unmap indata file.
 * [in, out] ctx: structure holds all input and output data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] none
 */
static void cat_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (outdata) {
        BIO_free_all(hash);
    }
    unmap_file(ctx->options->indata, ctx->cat_ctx->fileend);
    PKCS7_free(ctx->cat_ctx->p7);
    OPENSSL_free(ctx->cat_ctx);
    OPENSSL_free(ctx);
}

/*
 * CAT helper functions
 */

/*
 * Verify mapped CAT file and create CAT format specific structure.
 * [in] indata: mapped CAT file (unused)
 * [in] filesize: size of CAT file
 * [returns] pointer to CAT format specific structure
 */
static CAT_CTX *cat_ctx_get(char *indata, uint32_t filesize)
{
    CAT_CTX *cat_ctx;
    PKCS7 *p7 = pkcs7_get(indata, 0, filesize);

    if (!p7)
        return NULL; /* FAILED */
    cat_ctx = OPENSSL_zalloc(sizeof(CAT_CTX));
    cat_ctx->p7 = p7;
    cat_ctx->sigpos = 0;
    cat_ctx->siglen = filesize;
    cat_ctx->fileend = filesize;
    return cat_ctx; /* OK */
}

/*
 * Add "1.3.6.1.4.1.311.10.1" MS_CTL_OBJID signed attribute
 * [in, out] p7: new PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int cat_add_ms_ctl_object(PKCS7 *p7)
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
        V_ASN1_OBJECT, OBJ_txt2obj(MS_CTL_OBJID, 1)))
        return 0; /* FAILED */
    return 1; /* OK */
}

/*
 * Sign the MS CTL blob.
 * Certificate Trust List (CTL) is a list of file names or thumbprints.
 * All the items in this list are authenticated (approved) by the signing entity.
 * [in, out] p7: new PKCS#7 signature
 * [in] contents: Certificate Trust List (CTL)
 * [returns] 0 on error or 1 on success
 */
static int cat_sign_ms_ctl_content(PKCS7 *p7, PKCS7 *contents)
{
    u_char *content;
    int seqhdrlen, content_length;

    seqhdrlen = asn1_simple_hdr_len(contents->d.other->value.sequence->data,
        contents->d.other->value.sequence->length);
    content = contents->d.other->value.sequence->data + seqhdrlen;
    content_length = contents->d.other->value.sequence->length - seqhdrlen;

    if (!pkcs7_sign_content(p7, content, content_length)) {
        printf("Failed to sign content\n");
        return 0; /* FAILED */
    }
    if (!PKCS7_set_content(p7, PKCS7_dup(contents))) {
        printf("PKCS7_set_content failed\n");
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
