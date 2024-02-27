/*
 * Script file support library
 *
 * Copyright (C) 2021-2024 Michał Trojnara <Michal.Trojnara@stunnel.org>
 */

#include "osslsigncode.h"
#include "helpers.h"
#include "utf.h"

typedef enum {comment_hash, comment_xml, comment_c, comment_not_found} comment_style;

typedef struct {
    const char *extension;
    comment_style comment;
} SCRIPT_FORMAT;

const SCRIPT_FORMAT supported_formats[] = {
    {".ps1",    comment_hash},
    {".ps1xml", comment_xml},
    {".psc1",   comment_xml},
    {".psd1",   comment_hash},
    {".psm1",   comment_hash},
    {".cdxml",  comment_xml},
    {".mof",    comment_c},
    {NULL,      comment_not_found},
};

const char *signature_header = "SIG # Begin signature block";
const char *signature_footer = "SIG # End signature block";

typedef struct {
    const char *open;
    const char *close;
} SCRIPT_COMMENT;

const SCRIPT_COMMENT comment_text[] = {
    [comment_hash] = {"# ", ""},
    [comment_xml]  = {"<!-- ", " -->"},
    [comment_c]    = {"/* ", " */"}
};

struct script_ctx_st {
    const SCRIPT_COMMENT *comment_text;
    int utf;
    uint32_t sigpos;
    uint32_t fileend;
};

#define LINE_MAX_LEN 100

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *script_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static ASN1_OBJECT *script_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static PKCS7 *script_pkcs7_contents_get(FILE_FORMAT_CTX *ctx, BIO *hash, const EVP_MD *md);
static int script_hash_length_get(FILE_FORMAT_CTX *ctx);
static int script_check_file(FILE_FORMAT_CTX *ctx, int detached);
static u_char *script_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md);
static int script_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *script_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static PKCS7 *script_pkcs7_extract_to_nest(FILE_FORMAT_CTX *ctx);
static int script_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int script_process_data(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *script_pkcs7_signature_new(FILE_FORMAT_CTX *ctx, BIO *hash);
static int script_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *script_bio_free(BIO *hash, BIO *outdata);
static void script_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_script = {
    .ctx_new        = script_ctx_new,
    .data_blob_get  = script_spc_sip_info_get,
    .pkcs7_contents_get = script_pkcs7_contents_get,
    .hash_length_get = script_hash_length_get,
    .check_file     = script_check_file,
    .digest_calc    = script_digest_calc,
    .verify_digests = script_verify_digests,
    .pkcs7_extract  = script_pkcs7_extract,
    .pkcs7_extract_to_nest = script_pkcs7_extract_to_nest,
    .remove_pkcs7   = script_remove_pkcs7,
    .process_data   = script_process_data,
    .pkcs7_signature_new = script_pkcs7_signature_new,
    .append_pkcs7   = script_append_pkcs7,
    .bio_free       = script_bio_free,
    .ctx_cleanup    = script_ctx_cleanup,
};

/* helper functions */
static SCRIPT_CTX *script_ctx_get(char *indata, uint32_t filesize, const SCRIPT_COMMENT *comment, int utf);
static int write_commented(FILE_FORMAT_CTX *ctx, BIO *outdata, const char *data, size_t length);
static int write_in_encoding(FILE_FORMAT_CTX *ctx, BIO *outdata, const char *line, size_t length);
static size_t utf8_to_utf16(const char *data, size_t len, uint16_t **out_utf16);
static size_t utf16_to_utf8(const uint16_t *data, size_t len, char **out_utf8);
static BIO *script_digest_calc_bio(FILE_FORMAT_CTX *ctx, const EVP_MD *md);
static int script_digest_convert(BIO *hash, FILE_FORMAT_CTX *ctx, size_t len);
static int script_write_bio(BIO *data, char *indata, size_t len);

/*
 * Allocate and return a script file format context.
 * [in, out] options: structure holds the input data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO (unused)
 * [returns] pointer to script file format context
 */
static FILE_FORMAT_CTX *script_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
    FILE_FORMAT_CTX *ctx;
    SCRIPT_CTX *script_ctx;
    const SCRIPT_FORMAT *fmt;
    uint32_t filesize;
    const uint8_t utf16_bom[] = {0xff, 0xfe};
    size_t name_len;
    int utf;

    /* squash the unused parameter warning */
    (void)outdata;

    /* find out whether our format is supported */
    name_len = strlen(options->infile);
    for (fmt = supported_formats; fmt->comment != comment_not_found; fmt++) {
        size_t ext_len = strlen(fmt->extension);
        if(name_len > ext_len && !strcasecmp(options->infile + name_len - ext_len, fmt->extension))
            break;
    }
    if (fmt->comment == comment_not_found)
        return NULL;
    printf("Script file format: %s\n", fmt->extension);

    filesize = get_file_size(options->infile);
    if (filesize == 0)
        return NULL; /* FAILED */

    options->indata = map_file(options->infile, filesize);
    if (!options->indata) {
        return NULL; /* FAILED */
    }
    utf = memcmp(options->indata, utf16_bom, sizeof utf16_bom) ? 8 : 16;

    /* initialize script context */
    script_ctx = script_ctx_get(options->indata, filesize, comment_text + fmt->comment, utf);
    if (!script_ctx) {
        unmap_file(options->indata, filesize);
        return NULL; /* FAILED */
    }

    /* initialize file format context */
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    memset(ctx, 0, sizeof(FILE_FORMAT_CTX));
    ctx->format = &file_format_script;
    ctx->options = options;
    ctx->script_ctx = script_ctx;

    if (hash)
        BIO_push(hash, BIO_new(BIO_s_null()));

    /* FIXME: user interface logic belongs to osslsigncode.c */
    if (options->pagehash == 1)
        printf("Warning: -ph option is only valid for PE files\n");
    if (options->jp >= 0)
        printf("Warning: -jp option is only valid for CAB files\n");
    return ctx;
}

/*
 * Allocate and return SpcSipInfo object.
 * Subject Interface Package (SIP) is an internal Microsoft API for
 * transforming arbitrary files into a digestible stream.
 * These ClassIDs are found in the indirect data section and identify
 * the type of processor needed to validate the signature.
 * https://github.com/sassoftware/relic/blob/620d0b75ec67c0158a8a9120950abe04327d922f/lib/authenticode/structs.go#L154
 * [out] p: SpcSipInfo data
 * [out] plen: SpcSipInfo data length
 * [in] ctx: structure holds input and output data
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_SIPINFO_OBJID
 */
static ASN1_OBJECT *script_spc_sip_info_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
    const u_char SpcUUIDSipInfoPs[] = {
        0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e,
        0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51
    };
    ASN1_OBJECT *dtype;
    SpcSipInfo *si = SpcSipInfo_new();

    /* squash the unused parameter warning */
    (void)ctx;

    ASN1_INTEGER_set(si->a, 65536);
    ASN1_INTEGER_set(si->b, 0);
    ASN1_INTEGER_set(si->c, 0);
    ASN1_INTEGER_set(si->d, 0);
    ASN1_INTEGER_set(si->e, 0);
    ASN1_INTEGER_set(si->f, 0);
    ASN1_OCTET_STRING_set(si->string, SpcUUIDSipInfoPs, sizeof SpcUUIDSipInfoPs);
    *plen = i2d_SpcSipInfo(si, NULL);
    *p = OPENSSL_malloc((size_t)*plen);
    i2d_SpcSipInfo(si, p);
    *p -= *plen;
    dtype = OBJ_txt2obj(SPC_SIPINFO_OBJID, 1);
    SpcSipInfo_free(si);
    return dtype; /* OK */
}

/*
 * Allocate and return a data content to be signed.
 * [in] ctx: structure holds input and output data
 * [in] hash: message digest BIO
 * [in] md: message digest algorithm
 * [returns] data content
 */
static PKCS7 *script_pkcs7_contents_get(FILE_FORMAT_CTX *ctx, BIO *hash, const EVP_MD *md)
{
    ASN1_OCTET_STRING *content;
    BIO *bhash;

    /* squash the unused parameter warning */
    (void)hash;

    bhash = script_digest_calc_bio(ctx, md);
    if (!bhash) {
        return NULL; /* FAILED */
    }
    content = spc_indirect_data_content_get(bhash, ctx);
    BIO_free_all(bhash);
    return pkcs7_set_content(content);
}

static int script_hash_length_get(FILE_FORMAT_CTX *ctx)
{
    return EVP_MD_size(ctx->options->md);
}

/*
 * Check if the signature exists.
 * FIXME: check it in pkcs7_extract()
 * [in, out] ctx: structure holds input and output data
 * [in] detached: embedded/detached PKCS#7 signature switch
 * [returns] 0 on error or 1 on success
 */
static int script_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
    if (!ctx) {
        printf("Init error\n\n");
        return 0; /* FAILED */
    }
    if (detached) {
        printf("Checking the specified catalog file\n\n");
        return 1; /* OK */
    }
    if (ctx->script_ctx->sigpos == 0
        || ctx->script_ctx->sigpos > ctx->script_ctx->fileend) {
        printf("No signature found\n\n");
        return 0; /* FAILED */
    }

    return 1; /* OK */
}

/*
 * Compute a simple sha1/sha256 message digest of the MSI file
 * for use with a catalog file.
 * [in] ctx: structure holds input and output data
 * [in] md: message digest algorithm
 * [returns] pointer to calculated message digest
 */
static u_char *script_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md)
{
    u_char *mdbuf;
    BIO *hash = BIO_new(BIO_f_md());

    if (!BIO_set_md(hash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(hash);
        return NULL; /* FAILED */
    }
    BIO_push(hash, BIO_new(BIO_s_null()));
    if (!script_write_bio(hash, ctx->options->indata, ctx->script_ctx->fileend)) {
        BIO_free_all(hash);
        return NULL; /* FAILED */
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(hash, (char*)mdbuf, EVP_MD_size(md));
    BIO_free_all(hash);
    return mdbuf; /* OK */
}

/*
 * Calculate the hash and compare to PKCS#7 signedData.
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int script_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    int mdtype = -1;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    u_char *cmdbuf = NULL;
    const EVP_MD *md;
    BIO *bhash;

    /* FIXME: this shared code most likely belongs in osslsigncode.c */
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
    md = EVP_get_digestbynid(mdtype);
    bhash = script_digest_calc_bio(ctx, md);
    if (!bhash)
        return 0; /* FAILED */

    cmdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)cmdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);

    if (!compare_digests(mdbuf, cmdbuf, mdtype)) {
        printf("Signature verification: failed\n\n");
        OPENSSL_free(cmdbuf);
        return 0; /* FAILED */
    }
    OPENSSL_free(cmdbuf);
    return 1; /* OK */
}

/*
 * Extract existing signature in DER format.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *script_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
    const char *signature_data = ctx->options->indata + ctx->script_ctx->sigpos;
    size_t signature_len = ctx->script_ctx->fileend - ctx->script_ctx->sigpos;
    size_t base64_len, der_max_length, der_length;
    char *ptr;
    BIO *bio_mem, *bio_b64 = NULL;
    char *base64_data = NULL;
    char *der_data = NULL;
    const char *der_tmp;
    char *clean_base64 = NULL;
    int clean_base64_len = 0;
    const char *open_tag = ctx->script_ctx->comment_text->open;
    const char *close_tag = ctx->script_ctx->comment_text->close;
    size_t open_tag_len = strlen(open_tag);
    size_t close_tag_len = strlen(close_tag);
    size_t signature_header_len = strlen(signature_header);
    size_t signature_footer_len = strlen(signature_footer);
    PKCS7 *retval = NULL;

    /* extract Base64 signature */
    if (ctx->script_ctx->utf == 8) {
        base64_len = signature_len;
        base64_data = OPENSSL_malloc(base64_len);
        memcpy(base64_data, signature_data, base64_len);
    } else {
        base64_len = utf16_to_utf8((const void *)signature_data,
            signature_len, &base64_data);
    }

    /* allocate memory for cleaned Base64 */
    clean_base64 = OPENSSL_malloc(base64_len);
    if (!clean_base64) {
        printf("Malloc failed\n");
        goto cleanup;
    }

    /* copy clean Base64 data */
    for (ptr = base64_data;;) {
        /* find the opening tag */
        for(;;) {
            if (ptr + open_tag_len >= base64_data + base64_len) {
                printf("Signature line too long\n");
                goto cleanup;
            }
            if (!memcmp(ptr, open_tag, (size_t)open_tag_len)) {
                ptr += open_tag_len;
                break;
            }
            ptr++;
        }
        /* process signature_header and signature_footer */
        if (ptr + signature_header_len < base64_data + base64_len &&
                !memcmp(ptr, signature_header, signature_header_len))
            ptr += signature_header_len;
        if (ptr + signature_footer_len <= base64_data + base64_len &&
                !memcmp(ptr, signature_footer, signature_footer_len))
            break; /* success */

        /* copy until the closing tag */
        for(;;) {
            if (ptr + close_tag_len >= base64_data + base64_len) {
                printf("Signature line too long\n");
                goto cleanup;
            }
            if (close_tag_len) {
                if (!memcmp(ptr, close_tag, (size_t)close_tag_len)) {
                    ptr += close_tag_len;
                    break;
                }
            }
            if (*ptr == '\r') {
                ptr++;
            } else if (*ptr == '\n') {
                ptr++;
                break;
            } else {
                clean_base64[clean_base64_len++] = *ptr++;
            }
        }
    }

    /* prepare for Base64 decoding */
    bio_mem = BIO_new_mem_buf(clean_base64, clean_base64_len);
    bio_b64 = BIO_new(BIO_f_base64());
    BIO_push(bio_b64, bio_mem);
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    /* allocate memory for DER output */
    der_max_length = BIO_ctrl_pending(bio_b64);
    der_data = OPENSSL_malloc(der_max_length);
    if (!der_data)
        goto cleanup;

    /* decode Base64 to DER */
    if (!BIO_read_ex(bio_b64, der_data, der_max_length, &der_length))
        goto cleanup;
    if (der_length <= 0)
        goto cleanup;

    /* decode DER */
    der_tmp = der_data;
    retval = d2i_PKCS7(NULL, (const unsigned char **)&der_tmp, (int)der_length);

cleanup:
    OPENSSL_free(base64_data);
    OPENSSL_free(clean_base64);
    OPENSSL_free(der_data);
    BIO_free_all(bio_b64);
    return retval;
}

/*
 * Extract existing signature in DER format.
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *script_pkcs7_extract_to_nest(FILE_FORMAT_CTX *ctx)
{
    return script_pkcs7_extract(ctx);
}

/*
 * Remove existing signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int script_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    /* squash the unused parameter warning */
    (void)hash;
    if (ctx->script_ctx->sigpos == 0
        || ctx->script_ctx->sigpos > ctx->script_ctx->fileend) {
        return 1; /* FAILED, no signature */
    }
    if (!script_write_bio(outdata, ctx->options->indata, ctx->script_ctx->sigpos)) {
        return 1; /* FAILED */
    }
    return 0; /* OK */
}

/*
 * Initialize outdata file and calculate a hash (message digest) of data.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int script_process_data(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (ctx->script_ctx->sigpos > 0) {
        /* Strip current signature */
        ctx->script_ctx->fileend = ctx->script_ctx->sigpos;
    }
    if (!script_write_bio(outdata, ctx->options->indata, ctx->script_ctx->fileend))
        return 1; /* FAILED */
    if (!script_digest_convert(hash, ctx, ctx->script_ctx->fileend))
        return 1; /* FAILED */
    return 0; /* OK */
}

/*
 * Create a new PKCS#7 signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *script_pkcs7_signature_new(FILE_FORMAT_CTX *ctx, BIO *hash)
{
    ASN1_OCTET_STRING *content;
    PKCS7 *p7 = pkcs7_create(ctx);

    if (!p7) {
        printf("Creating a new signature failed\n");
        return NULL; /* FAILED */
    }
    if (!add_indirect_data_object(p7)) {
        printf("Adding SPC_INDIRECT_DATA_OBJID failed\n");
        PKCS7_free(p7);
        return NULL; /* FAILED */
    }
    content = spc_indirect_data_content_get(hash, ctx);
    if (!content) {
        printf("Failed to get spcIndirectDataContent\n");
        return NULL; /* FAILED */
    }
    if (!sign_spc_indirect_data_content(p7, content)) {
        printf("Failed to set signed content\n");
        PKCS7_free(p7);
        ASN1_OCTET_STRING_free(content);
        return NULL; /* FAILED */
    }
    ASN1_OCTET_STRING_free(content);
    return p7;
}

/*
 * Append signature to the outfile.
 * [in, out] ctx: structure holds input and output data
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int script_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    BIO *bio, *b64;
    BUF_MEM *buffer;
    size_t i;
    static const char crlf[] = {0x0d, 0x0a};
    int ret = 1;

    /* convert to BASE64 */
    b64 = BIO_new(BIO_f_base64()); /* BIO for base64 encoding */
    if (!b64)
        return 1; /* FAILED */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem()); /* BIO to hold the base64 data */
    if (!bio) {
        BIO_free(b64);
        return 1; /* FAILED */
    }
    bio = BIO_push(b64, bio); /* chain base64 BIO onto memory BIO */
    if (!i2d_PKCS7_bio(bio, p7)) {
        BIO_free_all(bio);
        return 1; /* FAILED */
    }
    (void)BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer);
    (void)BIO_set_close(bio, BIO_NOCLOSE);

    /* split to individual lines and write to outdata */
    if (!write_commented(ctx, outdata, signature_header, strlen(signature_header)))
        goto cleanup;
    for (i = 0; i < buffer->length; i += 64) {
        if (!write_commented(ctx, outdata, buffer->data + i,
            buffer->length - i < 64 ? buffer->length - i : 64)) {
            goto cleanup;
        }
    }
    if (!write_commented(ctx, outdata, signature_footer, strlen(signature_footer)))
        goto cleanup;

    /* signtool expects CRLF terminator at the end of the text file */
    if (!write_in_encoding(ctx, outdata, crlf, sizeof crlf))
        goto cleanup;
    ret = 0;  /* OK */

cleanup:
    BUF_MEM_free(buffer);
    BIO_free_all(bio);
    return ret;
}

/*
 * Free up an entire outdata BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] none
 */
static BIO *script_bio_free(BIO *hash, BIO *outdata)
{
    BIO_free_all(hash);
    BIO_free_all(outdata);
    /* FIXME: why doesn't the function return void instead of BIO *? */
    return NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and script format specific structures.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] none
 */
static void script_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (outdata) {
        BIO_free_all(hash);
        BIO_free_all(outdata);
    }
    unmap_file(ctx->options->indata, ctx->script_ctx->fileend);
    OPENSSL_free(ctx->script_ctx);
    OPENSSL_free(ctx);
}

/*
 * Script helper functions
 */

static SCRIPT_CTX *script_ctx_get(char *indata, uint32_t filesize, const SCRIPT_COMMENT *comment, int utf)
{
    SCRIPT_CTX *script_ctx;

    const char *input_pos, *signature_pos, *ptr;
    uint32_t line[LINE_MAX_LEN], commented_header[40], cr, lf;
    size_t sig_pos = 0, line_pos = 0, commented_header_len = 0;
    size_t commented_header_size = sizeof commented_header / sizeof(uint32_t);

    utf8DecodeRune("\r", 1, &cr);
    utf8DecodeRune("\n", 1, &lf);

    /* compute runes for the commented signature header */
    for (ptr = comment->open;
            *ptr && commented_header_len < commented_header_size;
            commented_header_len++)
        ptr = utf8DecodeRune(ptr, 1, commented_header + commented_header_len);
    for (ptr = signature_header;
            *ptr && commented_header_len < commented_header_size;
            commented_header_len++)
        ptr = utf8DecodeRune(ptr, 1, commented_header + commented_header_len);
    for (ptr = comment->close;
            *ptr && commented_header_len < commented_header_size;
            commented_header_len++)
        ptr = utf8DecodeRune(ptr, 1, commented_header + commented_header_len);

    /* find the signature header */
    for (signature_pos = input_pos = indata; input_pos < indata + filesize; ) {
        const char *input_prev = input_pos;

        input_pos = utf == 8 ?
            utf8DecodeRune(input_pos,
                (size_t)(indata + filesize - input_pos),
                line + line_pos) :
            (const char *)utf16DecodeRune((const void *)input_pos,
                (size_t)(indata + filesize - input_pos)/2,
                line + line_pos);

        if (!memcmp(line + line_pos, &lf, sizeof lf)) {
            if (line_pos >= commented_header_len &&
                    !memcmp(line, commented_header, commented_header_len * sizeof(uint32_t))) {
                sig_pos = (size_t)(signature_pos - indata);
                if (!memcmp(line + line_pos - 1, &cr, sizeof cr))
                    sig_pos -= (size_t)utf / 8;
                break; /* SUCCEEDED */
            }
            line_pos = 0;
            signature_pos = input_prev; /* previous line */
        } else if (line_pos < LINE_MAX_LEN - 1) {
            line_pos++; /* we can ignore lines longer than our buffer */
        }
    }
    printf("Signature position: %zu\n", sig_pos);

    script_ctx = OPENSSL_malloc(sizeof(SCRIPT_CTX));
    script_ctx->comment_text = comment;
    script_ctx->utf = utf;
    script_ctx->fileend = filesize;
    script_ctx->sigpos = (uint32_t)sig_pos;
    return script_ctx; /* OK */
}

/* write a commented line to the bio:
 * - prepend with CRLF ("\r\n")
 * - add opening/closing comment tags
 * - adjust encoding if needed
 * [returns] 0 on error or 1 on success
 */
static int write_commented(FILE_FORMAT_CTX *ctx, BIO *outdata, const char *data, size_t length)
{
    const char *open_tag = ctx->script_ctx->comment_text->open;
    const char *close_tag = ctx->script_ctx->comment_text->close;
    size_t open_tag_len = strlen(open_tag);
    size_t close_tag_len = strlen(close_tag);
    char *line;

    /* the buffer needs to be long enough for:
     * - CRLF ("\r\n")
     * - opening tag
     * - up to 64 bytes of data
     * - closing tag
     * - trailing NUL ("\0") */
    line = OPENSSL_malloc(2 + open_tag_len + length + close_tag_len + 1);
    strcpy(line, "\r\n");
    strcat(line, open_tag);
    memcpy(line + 2 + open_tag_len, data, length);
    line[2 + open_tag_len + length] = '\0';
    strcat(line, close_tag);

    /* adjust encoding */
    if (!write_in_encoding(ctx, outdata, line, strlen(line))) {
        OPENSSL_free(line);
        return 0; /* FAILED */
    }
    OPENSSL_free(line);
    return 1; /* OK */
}

/* adjust encoding if needed
 * [returns] 0 on error or 1 on success
 */
static int write_in_encoding(FILE_FORMAT_CTX *ctx, BIO *outdata, const char *line, size_t length)
{
    size_t written;
    if (ctx->script_ctx->utf == 8) {
        if (!BIO_write_ex(outdata, line, length, &written)
            || written != length) {
            return 0; /* FAILED */
        }
    } else {
        uint16_t *utf16_data = NULL;
        size_t utf16_len = utf8_to_utf16(line, length, &utf16_data);

        if (!BIO_write_ex(outdata, utf16_data, utf16_len, &written)
            || written != utf16_len) {
            OPENSSL_free(utf16_data);
            return 0; /* FAILED */
        }
        OPENSSL_free(utf16_data);
    }
    return 1; /* OK */
}

/* convert len bytes of UTF-8 to UTF-16
 * return the number of output bytes
 */
static size_t utf8_to_utf16(const char *data, size_t len, uint16_t **out_utf16)
{
    size_t utf16_len = utf8UTF16Count(data, len);
    *out_utf16 = OPENSSL_malloc(utf16_len * sizeof(uint16_t));
    if (!*out_utf16)
        return 0; /* memory allocation failed */

    const char *s = data;
    uint16_t *d = *out_utf16;
    uint32_t rune;
    size_t remaining_len = len;

    while (remaining_len > 0) {
        s = utf8DecodeRune(s, remaining_len, &rune);
        if (!s || s < data)
            break; /* invalid UTF-8 sequence */
        size_t consumed = (size_t)(s - data);

        remaining_len -= consumed;
        data = s;
        d += utf16EncodeRune(rune, d);
    }
    return (size_t)(2 * (d - *out_utf16));
}

/* convert len bytes of UTF-16 to UTF-8
 * return the number of output bytes
 */
static size_t utf16_to_utf8(const uint16_t *data, size_t len, char **out_utf8)
{
    size_t utf8_len = utf16UTF8Count(data, len/2);
    *out_utf8 = OPENSSL_malloc(utf8_len);
    if (!*out_utf8)
        return 0; /* memory allocation failed */

    const uint16_t *s = data;
    char *d = *out_utf8;
    uint32_t rune;
    size_t remaining_len = len/2;

    while (remaining_len > 0) {
        s = utf16DecodeRune(s, remaining_len, &rune);
        if (!s || s < data)
            break; /* invalid UTF-16 sequence */
        size_t consumed = (size_t)(s - data);

        remaining_len -= consumed;
        data = s;
        d += utf8EncodeRune(rune, d);
    }
    return (size_t)(d - *out_utf8);
}

/*
 * Compute a message digest value of a signed or unsigned script file.
 * [in] ctx: structure holds input and output data
 * [in] md: message digest algorithm
 * [returns] calculated message digest BIO
 */
static BIO *script_digest_calc_bio(FILE_FORMAT_CTX *ctx, const EVP_MD *md)
{
    size_t fileend;
    BIO *hash = BIO_new(BIO_f_md());

    if (ctx->script_ctx->sigpos)
        fileend = ctx->script_ctx->sigpos;
    else
        fileend = ctx->script_ctx->fileend;

    if (!BIO_set_md(hash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(hash);
        return NULL; /* FAILED */
    }
    BIO_push(hash, BIO_new(BIO_s_null()));
    if (!script_digest_convert(hash, ctx, fileend)) {
        printf("Unable calc a message digest value\n");
        BIO_free_all(hash);
        return NULL; /* FAILED */
    }
    return hash;
}

/*
 * Compute a message digest value
 * [in, out] hash: message digest BIO
 * [in] ctx: structure holds input and output data
 * [in] len: mapped file length
 * [returns] 0 on error or 1 on success
 */
static int script_digest_convert(BIO *hash, FILE_FORMAT_CTX *ctx, size_t len)
{
    if (ctx->script_ctx->utf == 8) { /* need to convert to UTF-16 */
        uint16_t *utf16_data = NULL;
        size_t utf16_len = utf8_to_utf16(ctx->options->indata,
            len, &utf16_data);

        if (!script_write_bio(hash, (char *)utf16_data, utf16_len)) {
            OPENSSL_free(utf16_data);
            return 0; /* FAILED */
        }
        OPENSSL_free(utf16_data);
    } else { /* already UTF-16 -> no need to convert */
        if (!script_write_bio(hash, ctx->options->indata, len)) {
            return 0; /* FAILED */
        }
    }
    return 1; /* OK */
}

/*
 * Write len bytes from data to BIO
 * [in, out] bio: message digest or outdata BIO
 * [in] indata: mapped file
 * [in] len: indata length
 * [returns] 0 on error or 1 on success
 */
static int script_write_bio(BIO *bio, char *indata, size_t len)
{
    size_t i = 0, written;

    while (len > 0) {
        if (!BIO_write_ex(bio, indata + i, len, &written))
            return 0; /* FAILED */
        len -= written;
        i += written;
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
