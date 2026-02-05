/*
 * CAT file support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * Catalog files are a bit odd, in that they are only a PKCS7 blob.
 * CAT files do not support nesting (multiple signature)
 */

#include "osslsigncode.h"
#include "helpers.h"

typedef struct {
    ASN1_BMPSTRING *tag;
    ASN1_INTEGER *flags;
    ASN1_OCTET_STRING *value;
} CatNameValueContent;

DECLARE_ASN1_FUNCTIONS(CatNameValueContent)

ASN1_SEQUENCE(CatNameValueContent) = {
    ASN1_SIMPLE(CatNameValueContent, tag, ASN1_BMPSTRING),
    ASN1_SIMPLE(CatNameValueContent, flags, ASN1_INTEGER),
    ASN1_SIMPLE(CatNameValueContent, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CatNameValueContent)

IMPLEMENT_ASN1_FUNCTIONS(CatNameValueContent)

struct cat_ctx_st {
    uint32_t sigpos;
    uint32_t siglen;
    uint32_t fileend;
    PKCS7 *p7;
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *cat_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static int cat_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *cat_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static PKCS7 *cat_pkcs7_signature_new(FILE_FORMAT_CTX *ctx, BIO *hash);
static int cat_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static void cat_bio_free(BIO *hash, BIO *outdata);
static void cat_ctx_cleanup(FILE_FORMAT_CTX *ctx);

FILE_FORMAT file_format_cat = {
    .ctx_new = cat_ctx_new,
    .verify_digests = cat_verify_digests,
    .pkcs7_extract = cat_pkcs7_extract,
    .pkcs7_signature_new = cat_pkcs7_signature_new,
    .append_pkcs7 = cat_append_pkcs7,
    .bio_free = cat_bio_free,
    .ctx_cleanup = cat_ctx_cleanup,
};

/* Prototypes */
static CAT_CTX *cat_ctx_get(char *indata, uint32_t filesize);
static int cat_add_content_type(PKCS7 *p7, PKCS7 *cursig);
static int cat_sign_content(PKCS7 *p7, PKCS7 *contents);
static int cat_list_content(PKCS7 *p7);
static int cat_print_content_member_digest(ASN1_TYPE *content);
static int cat_print_content_member_name(ASN1_TYPE *content);
static void cat_print_base64(ASN1_OCTET_STRING *value);
static void cat_print_utf16_as_ascii(ASN1_OCTET_STRING *value);
static int cat_check_file(FILE_FORMAT_CTX *ctx);

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

    if (options->cmd == CMD_REMOVE || options->cmd==CMD_ATTACH || options->cmd == CMD_EXTRACT_DATA) {
        fprintf(stderr, "Unsupported command\n");
        return NULL; /* FAILED */
    }
    filesize = get_file_size(options->infile);
    if (filesize == 0)
        return NULL; /* FAILED */

    options->indata = map_file(options->infile, filesize);
    if (!options->indata) {
        return NULL; /* FAILED */
    }
    cat_ctx = cat_ctx_get(options->indata, filesize);
    if (!cat_ctx) {
        unmap_file(options->indata, filesize);
        return NULL; /* FAILED */
    }
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    ctx->format = &file_format_cat;
    ctx->options = options;
    ctx->cat_ctx = cat_ctx;

    /* Push hash on outdata, if hash is NULL the function does nothing */
    BIO_push(hash, outdata);

    if (options->cmd == CMD_VERIFY)
        printf("Warning: Use -catalog option to verify that a file, listed in catalog file, is signed\n");
    if (options->jp >= 0)
        printf("Warning: -jp option is only valid for CAB files\n");
    if (options->pagehash == 1)
        printf("Warning: -ph option is only valid for PE files\n");
    if (options->add_msi_dse == 1)
        printf("Warning: -add-msi-dse option is only valid for MSI files\n");
    return ctx;
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
    if (!cat_check_file(ctx)) {
        return NULL; /* FAILED */
    }
    return PKCS7_dup(ctx->cat_ctx->p7);
}

/*
 * Create a new PKCS#7 signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *cat_pkcs7_signature_new(FILE_FORMAT_CTX *ctx, BIO *hash)
{
    PKCS7 *p7 = NULL;

    /* squash unused parameter warnings */
    (void)hash;

    p7 = pkcs7_create(ctx);
    if (!p7) {
        fprintf(stderr, "Creating a new signature failed\n");
        return NULL; /* FAILED */
    }
    if (!ctx->cat_ctx->p7 || !ctx->cat_ctx->p7->d.sign || !ctx->cat_ctx->p7->d.sign->contents) {
        fprintf(stderr, "Failed to get content\n");
        PKCS7_free(p7);
        return NULL; /* FAILED */
    }
    if (!cat_add_content_type(p7, ctx->cat_ctx->p7)) {
        fprintf(stderr, "Adding content type failed\n");
        PKCS7_free(p7);
        return NULL; /* FAILED */
    }
    if (!cat_sign_content(p7, ctx->cat_ctx->p7->d.sign->contents)) {
        fprintf(stderr, "Failed to set signed content\n");
        PKCS7_free(p7);
        return NULL; /* FAILED */
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
static int cat_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    return data_write_pkcs7(ctx, outdata, p7);
}

/*
 * Free up an entire message digest BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO (unused)
 * [returns] none
 */
static void cat_bio_free(BIO *hash, BIO *outdata)
{
    /* squash the unused parameter warning */
    (void)outdata;
    BIO_free_all(hash);
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and CAT format specific structure,
 * unmap indata file.
 * [in, out] ctx: structure holds all input and output data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] none
 */
static void cat_ctx_cleanup(FILE_FORMAT_CTX *ctx)
{
    unmap_file(ctx->options->indata, ctx->cat_ctx->fileend);
    PKCS7_free(ctx->cat_ctx->p7);
    OPENSSL_free(ctx->cat_ctx);
    OPENSSL_free(ctx);
}

/*
 * CAT helper functions
 */

/*
 * Verify mapped PKCS#7 (CAT) file and create CAT format specific structure.
 * [in] indata: mapped file
 * [in] filesize: size of file
 * [returns] pointer to CAT format specific structure
 */
static CAT_CTX *cat_ctx_get(char *indata, uint32_t filesize)
{
    CAT_CTX *cat_ctx;
    PKCS7 *p7;

    p7 = pkcs7_read_data(indata, filesize);
    if (!p7)
        return NULL; /* FAILED */
    if (!PKCS7_type_is_signed(p7)) {
        PKCS7_free(p7);
        return NULL; /* FAILED */
    }
    cat_ctx = OPENSSL_zalloc(sizeof(CAT_CTX));
    cat_ctx->p7 = p7;
    cat_ctx->sigpos = 0;
    cat_ctx->siglen = filesize;
    cat_ctx->fileend = filesize;
    return cat_ctx; /* OK */
}

/*
 * Add a content type OID to the PKCS#7 signature structure.
 * The content type can be:
 * - "1.3.6.1.4.1.311.10.1" (MS_CTL_OBJID) for Certificate Trust Lists (CTL),
 * - "1.3.6.1.4.1.311.2.1.4" (SPC_INDIRECT_DATA_OBJID) for Authenticode data.
 * [in, out] p7: new PKCS#7 signature
 * [in] cursig: current PKCS#7 signature to determine content type
 * [returns] 0 on error or 1 on success
 */
static int cat_add_content_type(PKCS7 *p7, PKCS7 *cursig)
{
    const char *content_type;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;

    if (is_content_type(cursig, SPC_INDIRECT_DATA_OBJID)) {
        /* Authenticode content */
        content_type = SPC_INDIRECT_DATA_OBJID;
    } else if (is_content_type(cursig, MS_CTL_OBJID)) {
        /* Certificate Trust List (CTL) */
        content_type = MS_CTL_OBJID;
    } else {
        fprintf(stderr, "Unsupported content type\n");
        return 0; /* FAILED */
    }
    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        return 0; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return 0; /* FAILED */
    if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
        V_ASN1_OBJECT, OBJ_txt2obj(content_type, 1)))
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
static int cat_sign_content(PKCS7 *p7, PKCS7 *contents)
{
    u_char *content;
    int seqhdrlen, content_length;

    if (!contents->d.other || !contents->d.other->value.sequence
          || !contents->d.other->value.sequence->data) {
        fprintf(stderr, "Failed to get content value\n");
        return 0; /* FAILED */
    }
    seqhdrlen = asn1_simple_hdr_len(contents->d.other->value.sequence->data,
        contents->d.other->value.sequence->length);
    content = contents->d.other->value.sequence->data + seqhdrlen;
    content_length = contents->d.other->value.sequence->length - seqhdrlen;

    if (!pkcs7_sign_content(p7, content, content_length)) {
        fprintf(stderr, "Failed to sign content\n");
        return 0; /* FAILED */
    }
    if (!PKCS7_set_content(p7, PKCS7_dup(contents))) {
        fprintf(stderr, "PKCS7_set_content failed\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Print each member of the CAT file by using the "-verbose" option.
 * [in, out] p7: catalog file to verify
 * [returns] 1 on error or 0 on success
 */
static int cat_list_content(PKCS7 *p7)
{
    MsCtlContent *ctlc;
    int i;

    ctlc = ms_ctl_content_get(p7);
    if (!ctlc) {
        fprintf(stderr, "Failed to extract MS_CTL_OBJID data\n");
        return 1; /* FAILED */
    }
    printf("\nCatalog members:\n");
    for (i = 0; i < sk_CatalogInfo_num(ctlc->header_attributes); i++) {
        int j, found = 0;
        CatalogInfo *header_attr = sk_CatalogInfo_value(ctlc->header_attributes, i);
        if (header_attr == NULL)
            continue;
        for (j = 0; j < sk_CatalogAuthAttr_num(header_attr->attributes); j++) {
            char object_txt[128];
            CatalogAuthAttr *attribute;
            ASN1_TYPE *content;

            attribute = sk_CatalogAuthAttr_value(header_attr->attributes, j);
            if (!attribute)
                continue;
            content = catalog_content_get(attribute);
            if (!content)
                continue;
            object_txt[0] = 0x00;
            OBJ_obj2txt(object_txt, sizeof object_txt, attribute->type, 1);
            if (!strcmp(object_txt, CAT_NAMEVALUE_OBJID)) {
                /* CAT_NAMEVALUE_OBJID OID: 1.3.6.1.4.1.311.12.2.1 */
                found |= cat_print_content_member_name(content);
            } else if (!strcmp(object_txt, SPC_INDIRECT_DATA_OBJID)) {
                /* SPC_INDIRECT_DATA_OBJID OID: 1.3.6.1.4.1.311.2.1.4 */
                found |= cat_print_content_member_digest(content);
            }
            ASN1_TYPE_free(content);
        }
        if (found)
            printf("\n");
    }
    MsCtlContent_free(ctlc);
    ERR_print_errors_fp(stderr);
    return 0; /* OK */
}

/*
 * Print a hash algorithm and a message digest from the SPC_INDIRECT_DATA_OBJID attribute.
 * [in] content: catalog file content
 * [returns] 0 on error or 1 on success
 */
static int cat_print_content_member_digest(ASN1_TYPE *content)
{
    SpcIndirectDataContent *idc;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    const u_char *data ;
    int mdtype = -1;
    ASN1_STRING *value;

    value = content->value.sequence;
    data = ASN1_STRING_get0_data(value);
    idc = d2i_SpcIndirectDataContent(NULL, &data, ASN1_STRING_length(value));
    if (!idc)
        return 0; /* FAILED */
    if (spc_indirect_data_content_get_digest(idc, mdbuf, &mdtype) < 0) {
        fprintf(stderr, "Failed to extract message digest from signature\n\n");
        SpcIndirectDataContent_free(idc);
        return 0; /* FAILED */
    }
    SpcIndirectDataContent_free(idc);
    printf("\tHash algorithm: %s\n", OBJ_nid2sn(mdtype));
    print_hash("\tMessage digest", "", mdbuf, EVP_MD_size(EVP_get_digestbynid(mdtype)));
    return 1; /* OK */
}

/*
 * Print a file name from the CAT_NAMEVALUE_OBJID attribute.
 * [in] content: catalog file content
 * [returns] 0 on error or 1 on success
 */
static int cat_print_content_member_name(ASN1_TYPE *content)
{
    CatNameValueContent *nvc;
    const u_char *data = NULL;
    ASN1_STRING *value;

    value = content->value.sequence;
    data = ASN1_STRING_get0_data(value);
    nvc = d2i_CatNameValueContent(NULL, &data, ASN1_STRING_length(value));
    if (!nvc) {
        return 0; /* FAILED */
    }
    printf("\tFile name: ");
    if (ASN1_INTEGER_get(nvc->flags) & 0x00020000) {
        cat_print_base64(nvc->value);
    } else {
        cat_print_utf16_as_ascii(nvc->value);
    }
    printf("\n");
    CatNameValueContent_free(nvc);
    return 1; /* OK */
}

/*
 * Print a CAT_NAMEVALUE_OBJID attribute represented in base-64 encoding.
 * [in] value: catalog member file name
 * [returns] none
 */
static void cat_print_base64(ASN1_OCTET_STRING *value)
{
    BIO *stdbio, *b64;
    stdbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    stdbio = BIO_push(b64, stdbio);
    ASN1_STRING_print_ex(stdbio, value, 0);
    BIO_free_all(stdbio);
}

/*
 * Print a CAT_NAMEVALUE_OBJID attribute represented in plaintext.
 * [in] value: catalog member file name
 * [returns] none
 */
static void cat_print_utf16_as_ascii(ASN1_OCTET_STRING *value)
{
    const u_char *data;
    int len, i;

    data = ASN1_STRING_get0_data(value);
    len = ASN1_STRING_length(value);
    for (i = 0; i < len && (data[i] || data[i+1]); i+=2)
        putchar(isprint(data[i]) && !data[i+1] ? data[i] : '.');
}

/*
 * Check if the signature exists.
 * [in, out] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int cat_check_file(FILE_FORMAT_CTX *ctx)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;

    if (!ctx) {
        fprintf(stderr, "Init error\n");
        return 0; /* FAILED */
    }
    signer_info = PKCS7_get_signer_info(ctx->cat_ctx->p7);
    if (!signer_info) {
        fprintf(stderr, "Failed catalog file\n");
        return 0; /* FAILED */
    }
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si) {
        fprintf(stderr, "No signature found\n");
        return 0; /* FAILED */
    }
    if (ctx->options->verbose) {
        (void)cat_list_content(ctx->cat_ctx->p7);
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
