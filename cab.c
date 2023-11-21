/*
 * CAB file support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 * Reference specifications:
 * https://www.file-recovery.com/cab-signature-format.htm
 * https://learn.microsoft.com/en-us/previous-versions/ms974336(v=msdn.10)
 */

#include "osslsigncode.h"
#include "helpers.h"

/*
 * FLAG_PREV_CABINET is set if the cabinet file is not the first in a set
 * of cabinet files. When this bit is set, the szCabinetPrev and szDiskPrev
 * fields are present in this CFHEADER.
 */
#define FLAG_PREV_CABINET 0x0001
/*
 * FLAG_NEXT_CABINET is set if the cabinet file is not the last in a set of
 * cabinet files. When this bit is set, the szCabinetNext and szDiskNext
* fields are present in this CFHEADER.
*/
#define FLAG_NEXT_CABINET 0x0002
/*
 * FLAG_RESERVE_PRESENT is set if the cabinet file contains any reserved
 * fields. When this bit is set, the cbCFHeader, cbCFFolder, and cbCFData
 * fields are present in this CFHEADER.
 */
#define FLAG_RESERVE_PRESENT 0x0004


struct cab_ctx_st {
    uint32_t header_size;
    uint32_t sigpos;
    uint32_t siglen;
    uint32_t fileend;
    uint16_t flags;
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *cab_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static ASN1_OBJECT *cab_obsolete_link_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx);
static int cab_hash_length_get(FILE_FORMAT_CTX *ctx);
static int cab_check_file(FILE_FORMAT_CTX *ctx, int detached);
static u_char *cab_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md);
static int cab_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7);
static PKCS7 *cab_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static int cab_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static PKCS7 *cab_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int cab_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static void cab_update_data_size(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *cab_bio_free(BIO *hash, BIO *outdata);
static void cab_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_cab = {
    .ctx_new = cab_ctx_new,
    .data_blob_get = cab_obsolete_link_get,
    .hash_length_get = cab_hash_length_get,
    .check_file = cab_check_file,
    .digest_calc = cab_digest_calc,
    .verify_digests = cab_verify_digests,
    .pkcs7_extract = cab_pkcs7_extract,
    .remove_pkcs7 = cab_remove_pkcs7,
    .pkcs7_prepare = cab_pkcs7_prepare,
    .append_pkcs7 = cab_append_pkcs7,
    .update_data_size = cab_update_data_size,
    .bio_free = cab_bio_free,
    .ctx_cleanup = cab_ctx_cleanup
};

/* Prototypes */
static CAB_CTX *cab_ctx_get(char *indata, uint32_t filesize);
static int cab_add_jp_attribute(PKCS7 *p7, int jp);
static size_t cab_write_optional_names(BIO *outdata, char *indata, size_t len, uint16_t flags);
static int cab_modify_header(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int cab_add_header(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

/*
 * FILE_FORMAT method definitions
 */

/*
 * Allocate and return a CAB file format context.
 * [in, out] options: structure holds the input data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] pointer to CAB file format context
 */
static FILE_FORMAT_CTX *cab_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata)
{
    FILE_FORMAT_CTX *ctx;
    CAB_CTX *cab_ctx;
    uint32_t filesize;

    filesize = get_file_size(options->infile);
    if (filesize == 0)
        return NULL; /* FAILED */

    options->indata = map_file(options->infile, filesize);
    if (!options->indata) {
        return NULL; /* FAILED */
    }
    if (memcmp(options->indata, "MSCF", 4)) {
        unmap_file(options->indata, filesize);
        return NULL; /* FAILED */
    }
    cab_ctx = cab_ctx_get(options->indata, filesize);
    if (!cab_ctx) {
        unmap_file(options->indata, filesize);
        return NULL; /* FAILED */
    }
    ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
    ctx->format = &file_format_cab;
    ctx->options = options;
    ctx->cab_ctx = cab_ctx;

    /* Push hash on outdata, if hash is NULL the function does nothing */
    BIO_push(hash, outdata);

    if (options->pagehash == 1)
        printf("Warning: -ph option is only valid for PE files\n");
    if (options->add_msi_dse == 1)
        printf("Warning: -add-msi-dse option is only valid for MSI files\n");
    return ctx;
}

/*
 * Allocate and return SpcLink object.
 * [out] p: SpcLink data
 * [out] plen: SpcLink data length
 * [in] ctx: structure holds input and output data (unused)
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_CAB_DATA_OBJID
 */
static ASN1_OBJECT *cab_obsolete_link_get(u_char **p, int *plen, FILE_FORMAT_CTX *ctx)
{
    ASN1_OBJECT *dtype;
    SpcLink *link = spc_link_obsolete_get();

    /* squash the unused parameter warning */
    (void)ctx;

    *plen = i2d_SpcLink(link, NULL);
    *p = OPENSSL_malloc((size_t)*plen);
    i2d_SpcLink(link, p);
    *p -= *plen;
    dtype = OBJ_txt2obj(SPC_CAB_DATA_OBJID, 1);
    SpcLink_free(link);
    return dtype; /* OK */
}

/*
 * [in] ctx: structure holds input and output data
 * [returns] the size of the message digest when passed an EVP_MD structure (the size of the hash)
 */
static int cab_hash_length_get(FILE_FORMAT_CTX *ctx)
{
    return EVP_MD_size(ctx->options->md);
}

/*
 * Check if the signature exists.
 * [in, out] ctx: structure holds input and output data
 * [in] detached: embedded/detached PKCS#7 signature switch
 * [returns] 0 on error or 1 on success
 */
static int cab_check_file(FILE_FORMAT_CTX *ctx, int detached)
{
    if (!ctx) {
        printf("Init error\n\n");
        return 0; /* FAILED */
    }
    if (detached) {
        printf("Checking the specified catalog file\n\n");
        return 1; /* OK */
    }
    if (ctx->cab_ctx->header_size != 20) {
        printf("No signature found\n\n");
        return 0; /* FAILED */
    }
    if (ctx->cab_ctx->sigpos == 0 || ctx->cab_ctx->siglen == 0
        || ctx->cab_ctx->sigpos > ctx->cab_ctx->fileend) {
        printf("No signature found\n\n");
        return 0; /* FAILED */
    }
    return 1; /* OK */
}

/*
 * Compute a message digest value of the signed or unsigned CAB file.
 * [in] ctx: structure holds input and output data
 * [in] md: message digest algorithm
 * [returns] pointer to calculated message digest
 */
static u_char *cab_digest_calc(FILE_FORMAT_CTX *ctx, const EVP_MD *md)
{
    uint32_t idx, fileend, coffFiles;
    u_char *mdbuf = NULL;
    BIO *bhash = BIO_new(BIO_f_md());

    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        return 0;  /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));

    /* u1 signature[4] 4643534D MSCF: 0-3 */
    BIO_write(bhash, ctx->options->indata, 4);
    /* u4 reserved1 00000000: 4-7 skipped */
    if (ctx->cab_ctx->sigpos) {
        uint16_t nfolders, flags;

        /*
         * u4 cbCabinet - size of this cabinet file in bytes: 8-11
         * u4 reserved2 00000000: 12-15
         */
        BIO_write(bhash, ctx->options->indata + 8, 8);
         /* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
        coffFiles = GET_UINT32_LE(ctx->options->indata + 16);
        BIO_write(bhash, ctx->options->indata + 16, 4);
        /*
         * u4 reserved3 00000000: 20-23
         * u1 versionMinor 03: 24
         * u1 versionMajor 01: 25
         */
        BIO_write(bhash, ctx->options->indata + 20, 6);
        /* u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27 */
        nfolders = GET_UINT16_LE(ctx->options->indata + 26);
        BIO_write(bhash, ctx->options->indata + 26, 2);
        /* u2 cFiles - number of CFFILE entries in this cabinet: 28-29 */
        BIO_write(bhash, ctx->options->indata + 28, 2);
        /* u2 flags: 30-31 */
        flags = GET_UINT16_LE(ctx->options->indata + 30);
        BIO_write(bhash, ctx->options->indata + 30, 2);
        /* u2 setID must be the same for all cabinets in a set: 32-33 */
        BIO_write(bhash, ctx->options->indata + 32, 2);
        /*
        * u2 iCabinet - number of this cabinet file in a set: 34-35 skipped
        * u2 cbCFHeader: 36-37 skipped
        * u1 cbCFFolder: 38 skipped
        * u1 cbCFData: 39 skipped
        * u22 abReserve: 40-55 skipped
        * - Additional data offset: 44-47 skipped
        * - Additional data size: 48-51 skipped
        */
        /* u22 abReserve: 56-59 */
        BIO_write(bhash, ctx->options->indata + 56, 4);
        idx = 60;
        fileend = ctx->cab_ctx->sigpos;
        /* TODO */
        if (flags & FLAG_PREV_CABINET) {
            uint8_t byte;
            /* szCabinetPrev */
            do {
                byte = GET_UINT8_LE(ctx->options->indata + idx);
                BIO_write(bhash, ctx->options->indata + idx, 1);
                idx++;
            } while (byte && idx < fileend);
            /* szDiskPrev */
            do {
                byte = GET_UINT8_LE(ctx->options->indata + idx);
                BIO_write(bhash, ctx->options->indata + idx, 1);
                idx++;
            } while (byte && idx < fileend);
        }
        if (flags & FLAG_NEXT_CABINET) {
            uint8_t byte;
            /* szCabinetNext */
            do {
                byte = GET_UINT8_LE(ctx->options->indata + idx);
                BIO_write(bhash, ctx->options->indata + idx, 1);
                idx++;
            } while (byte && idx < fileend);
            /* szDiskNext */
            do {
                byte = GET_UINT8_LE(ctx->options->indata + idx);
                BIO_write(bhash, ctx->options->indata + idx, 1);
                idx++;
            } while (byte && idx < fileend);
        }
        /*
         * (u8 * cFolders) CFFOLDER - structure contains information about
         * one of the folders or partial folders stored in this cabinet file
         */
        while (nfolders && idx < fileend) {
            BIO_write(bhash, ctx->options->indata + idx, 8);
            idx += 8;
            nfolders--;
        }
        if (idx != coffFiles) {
            printf("Corrupt coffFiles value: 0x%08X\n", coffFiles);
            BIO_free_all(bhash);
            return 0;  /* FAILED */
        }
    } else {
        /* read what's left of the unsigned CAB file */
        idx = 8;
        fileend = ctx->cab_ctx->fileend;
    }
    /* (variable) ab - the compressed data bytes */
    if (!bio_hash_data(bhash, ctx->options->indata, idx, fileend)) {
        printf("Unable to calculate digest\n");
        BIO_free_all(bhash);
        return 0;  /* FAILED */
    }
    mdbuf = OPENSSL_malloc((size_t)EVP_MD_size(md));
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    return mdbuf; /* OK */
}

/*
 * Calculate message digest and compare to value retrieved from PKCS#7 signedData.
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int cab_verify_digests(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    int mdtype = -1;
    const EVP_MD *md;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    u_char *cmdbuf;

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
    cmdbuf = cab_digest_calc(ctx, md);
    if (!cmdbuf) {
        printf("Failed to calculate message digest\n\n");
        return 0; /* FAILED */
    }
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
 * pointer to PKCS#7 structure
 */
static PKCS7 *cab_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
    if (ctx->cab_ctx->sigpos == 0 || ctx->cab_ctx->siglen == 0
        || ctx->cab_ctx->sigpos > ctx->cab_ctx->fileend) {
        return NULL; /* FAILED */
    }
    return pkcs7_get(ctx->options->indata, ctx->cab_ctx->sigpos, ctx->cab_ctx->siglen);
}

/*
 * Remove existing signature.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [out] outdata: outdata file BIO
 * [returns] 1 on error or 0 on success
 */
static int cab_remove_pkcs7(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    size_t i, written, len;
    uint32_t tmp;
    uint16_t nfolders, flags;
    char *buf = OPENSSL_malloc(SIZE_64K);

    /* squash the unused parameter warning */
    (void)hash;

    /*
     * u1 signature[4] 4643534D MSCF: 0-3
     * u4 reserved1 00000000: 4-7
     */
    BIO_write(outdata, ctx->options->indata, 8);
    /* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
    tmp = GET_UINT32_LE(ctx->options->indata + 8) - 24;
    PUT_UINT32_LE(tmp, buf);
    BIO_write(outdata, buf, 4);
    /* u4 reserved2 00000000: 12-15 */
    BIO_write(outdata, ctx->options->indata + 12, 4);
    /* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
    tmp = GET_UINT32_LE(ctx->options->indata + 16) - 24;
    PUT_UINT32_LE(tmp, buf);
    BIO_write(outdata, buf, 4);
    /*
     * u4 reserved3 00000000: 20-23
     * u1 versionMinor 03: 24
     * u1 versionMajor 01: 25
     * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
     * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
     */
    BIO_write(outdata, ctx->options->indata + 20, 10);
    /* u2 flags: 30-31 */
    flags = GET_UINT16_LE(ctx->options->indata + 30);
    /* coverity[result_independent_of_operands] only least significant byte is affected */
    PUT_UINT16_LE(flags & (FLAG_PREV_CABINET | FLAG_NEXT_CABINET), buf);
    BIO_write(outdata, buf, 2);
    /*
     * u2 setID must be the same for all cabinets in a set: 32-33
     * u2 iCabinet - number of this cabinet file in a set: 34-35
     */
    BIO_write(outdata, ctx->options->indata + 32, 4);
    i = cab_write_optional_names(outdata, ctx->options->indata, 60, flags);
    /*
     * (u8 * cFolders) CFFOLDER - structure contains information about
     * one of the folders or partial folders stored in this cabinet file
     */
    nfolders = GET_UINT16_LE(ctx->options->indata + 26);
    while (nfolders) {
        tmp = GET_UINT32_LE(ctx->options->indata + i);
        tmp -= 24;
        PUT_UINT32_LE(tmp, buf);
        BIO_write(outdata, buf, 4);
        BIO_write(outdata, ctx->options->indata + i + 4, 4);
        i+=8;
        nfolders--;
    }
    OPENSSL_free(buf);
    /* Write what's left - the compressed data bytes */
    len = ctx->cab_ctx->fileend - ctx->cab_ctx->siglen - i;
    while (len > 0) {
        if (!BIO_write_ex(outdata, ctx->options->indata + i, len, &written))
            return 1; /* FAILED */
        len -= written;
        i += written;
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
static PKCS7 *cab_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    PKCS7 *cursig = NULL, *p7 = NULL;

    /* Strip current signature and modify header */
    if (ctx->cab_ctx->header_size == 20) {
        if (!cab_modify_header(ctx, hash, outdata))
            return NULL; /* FAILED */
    } else {
        if (!cab_add_header(ctx, hash, outdata))
            return NULL; /* FAILED */
    }
    /* Obtain a current signature from previously-signed file */
    if ((ctx->options->cmd == CMD_SIGN && ctx->options->nest)
        || (ctx->options->cmd == CMD_ATTACH && ctx->options->nest)
        || ctx->options->cmd == CMD_ADD) {
        cursig = pkcs7_get(ctx->options->indata, ctx->cab_ctx->sigpos, ctx->cab_ctx->siglen);
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
        if (ctx->options->jp >= 0 && !cab_add_jp_attribute(p7, ctx->options->jp)) {
            printf("Adding jp attribute failed\n");
            PKCS7_free(p7);
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
static int cab_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    u_char *p = NULL;
    int len;       /* signature length */
    int padlen;    /* signature padding length */

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
 * Update additional data size.
 * Additional data size is located at offset 0x30 (from file beginning)
 * and consist of 4 bytes (little-endian order).
 * [in, out] ctx: structure holds input and output data
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] none
 */
static void cab_update_data_size(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
    int len, padlen;
    u_char buf[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* squash the unused parameter warning */
    (void)ctx;

    if (!p7) {
        /* CMD_REMOVE
         * additional header does not exist so additional data size is unused */
        return;
    }
    (void)BIO_seek(outdata, 0x30);
    len = i2d_PKCS7(p7, NULL);
    padlen = len % 8 ? 8 - len % 8 : 0;
    PUT_UINT32_LE(len + padlen, buf);
    BIO_write(outdata, buf, 4);
}

/*
 * Free up an entire message digest BIO chain.
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO (unused)
 * [returns] none
 */
static BIO *cab_bio_free(BIO *hash, BIO *outdata)
{
    /* squash the unused parameter warning */
    (void)outdata;

    BIO_free_all(hash);
    return NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure and CAB format specific structure,
 * unmap indata file.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [in] outdata: outdata file BIO
 * [returns] none
 */
static void cab_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    if (outdata) {
        BIO_free_all(hash);
    }
    unmap_file(ctx->options->indata, ctx->cab_ctx->fileend);
    OPENSSL_free(ctx->cab_ctx);
    OPENSSL_free(ctx);
}

/*
 * CAB helper functions
 */

/*
 * Verify mapped CAB file and create CAB format specific structure.
 * [in] indata: mapped CAB file
 * [in] filesize: size of CAB file
 * [returns] pointer to CAB format specific structure
 */
static CAB_CTX *cab_ctx_get(char *indata, uint32_t filesize)
{
    CAB_CTX *cab_ctx;
    uint32_t reserved, header_size = 0, sigpos = 0, siglen = 0;
    uint16_t flags;

    if (filesize < 44) {
        printf("CAB file is too short\n");
        return NULL; /* FAILED */
    }
    reserved = GET_UINT32_LE(indata + 4);
    if (reserved) {
        printf("Reserved1: 0x%08X\n", reserved);
        return NULL; /* FAILED */
    }
    /* flags specify bit-mapped values that indicate the presence of optional data */
    flags = GET_UINT16_LE(indata + 30);
    if (flags & FLAG_PREV_CABINET) {
        /* FLAG_NEXT_CABINET works */
        printf("Multivolume cabinet file is unsupported: flags 0x%04X\n", flags);
        return NULL; /* FAILED */
    }
    if (flags & FLAG_RESERVE_PRESENT) {
        /*
        * Additional headers is located at offset 36 (cbCFHeader, cbCFFolder, cbCFData);
        * size of header (4 bytes, little-endian order) must be 20 (checkpoint).
        */
        header_size = GET_UINT32_LE(indata + 36);
        if (header_size != 20) {
            printf("Additional header size: 0x%08X\n", header_size);
            return NULL; /* FAILED */
        }
        reserved = GET_UINT32_LE(indata + 40);
        if (reserved != 0x00100000) {
            printf("abReserved: 0x%08X\n", reserved);
            return NULL; /* FAILED */
        }
        /*
        * File size is defined at offset 8, however if additional header exists, this size is not valid.
        * sigpos - additional data offset is located at offset 44 (from file beginning)
        * and consist of 4 bytes (little-endian order)
        * siglen - additional data size is located at offset 48 (from file beginning)
        * and consist of 4 bytes (little-endian order)
        * If there are additional headers, size of the CAB archive file is calcualted
        * as additional data offset plus additional data size.
        */
        sigpos = GET_UINT32_LE(indata + 44);
        siglen = GET_UINT32_LE(indata + 48);
        if ((sigpos < filesize && sigpos + siglen != filesize) || (sigpos >= filesize)) {
            printf("Additional data offset:\t%u bytes\nAdditional data size:\t%u bytes\n",
                sigpos, siglen);
            printf("File size:\t\t%u bytes\n", filesize);
            return NULL; /* FAILED */
        }
        if ((sigpos > 0 && siglen == 0) || (sigpos == 0 && siglen > 0)) {
            printf("Corrupt signature\n");
            return NULL; /* FAILED */
        }
    }
    cab_ctx = OPENSSL_zalloc(sizeof(CAB_CTX));
    cab_ctx->header_size = header_size;
    cab_ctx->sigpos = sigpos;
    cab_ctx->siglen = siglen;
    cab_ctx->fileend = filesize;
    cab_ctx->flags = flags;
    return cab_ctx; /* OK */
}

/*
 * Add level of permissions in Microsoft Internet Explorer 4.x for CAB files,
 * only low level is supported.
 * [in, out] p7: PKCS#7 signature
 * [in] jp: low (0) level
 * [returns] 0 on error or 1 on success
 */
static int cab_add_jp_attribute(PKCS7 *p7, int jp)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;
    ASN1_STRING *astr;
    const u_char *attrs = NULL;
    const u_char java_attrs_low[] = {
        0x30, 0x06, 0x03, 0x02, 0x00, 0x01, 0x30, 0x00
    };

    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        return 0; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return 0; /* FAILED */
    switch (jp) {
        case 0:
            attrs = java_attrs_low;
            break;
        case 1:
            /* XXX */
        case 2:
            /* XXX */
        default:
            break;
        }
    if (attrs) {
        astr = ASN1_STRING_new();
        ASN1_STRING_set(astr, attrs, sizeof java_attrs_low);
        return PKCS7_add_signed_attribute(si, OBJ_txt2nid(MS_JAVA_SOMETHING),
                V_ASN1_SEQUENCE, astr);
    }
    return 1; /* OK */
}

/*
 * Write name of previous and next cabinet file.
 * Multivolume cabinet file is unsupported TODO.
 * [out] outdata: outdata file BIO
 * [in] indata: mapped CAB file
 * [in] len: offset
 * [in] flags: FLAG_PREV_CABINET, FLAG_NEXT_CABINET
 * [returns] offset
 */
static size_t cab_write_optional_names(BIO *outdata, char *indata, size_t i, uint16_t flags)
{
    if (flags & FLAG_PREV_CABINET) {
        /* szCabinetPrev */
        while (GET_UINT8_LE(indata + i)) {
            BIO_write(outdata, indata + i, 1);
            i++;
        }
        BIO_write(outdata, indata + i, 1);
        i++;
        /* szDiskPrev */
        while (GET_UINT8_LE(indata + i)) {
            BIO_write(outdata, indata + i, 1);
            i++;
        }
        BIO_write(outdata, indata + i, 1);
        i++;
    }
    if (flags & FLAG_NEXT_CABINET) {
        /* szCabinetNext */
        while (GET_UINT8_LE(indata + i)) {
            BIO_write(outdata, indata + i, 1);
            i++;
        }
        BIO_write(outdata, indata + i, 1);
        i++;
        /* szDiskNext */
        while (GET_UINT8_LE(indata + i)) {
            BIO_write(outdata, indata + i, 1);
            i++;
        }
        BIO_write(outdata, indata + i, 1);
        i++;
    }
    return i;
}

/*
 * Modify CAB header.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 0 on error or 1 on success
 */
static int cab_modify_header(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    size_t i, written, len;
    uint16_t nfolders, flags;
    u_char buf[] = {0x00, 0x00};

    /* u1 signature[4] 4643534D MSCF: 0-3 */
    BIO_write(hash, ctx->options->indata, 4);
    /* u4 reserved1 00000000: 4-7 */
    BIO_write(outdata, ctx->options->indata + 4, 4);
    /*
     * u4 cbCabinet - size of this cabinet file in bytes: 8-11
     * u4 reserved2 00000000: 12-15
     * u4 coffFiles - offset of the first CFFILE entry: 16-19
     * u4 reserved3 00000000: 20-23
     * u1 versionMinor 03: 24
     * u1 versionMajor 01: 25
     * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
     * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
     */
    BIO_write(hash, ctx->options->indata + 8, 22);
    /* u2 flags: 30-31 */
    flags = GET_UINT16_LE(ctx->options->indata + 30);
    PUT_UINT16_LE(flags, buf);
    BIO_write(hash, buf, 2);
    /* u2 setID must be the same for all cabinets in a set: 32-33 */
    BIO_write(hash, ctx->options->indata + 32, 2);
    /*
     * u2 iCabinet - number of this cabinet file in a set: 34-35
     * u2 cbCFHeader: 36-37
     * u1 cbCFFolder: 38
     * u1 cbCFData: 39
     * u16 abReserve: 40-55
     * - Additional data offset: 44-47
     * - Additional data size: 48-51
     */
    BIO_write(outdata, ctx->options->indata + 34, 22);
    /* u4 abReserve: 56-59 */
    BIO_write(hash, ctx->options->indata + 56, 4);

    i = cab_write_optional_names(outdata, ctx->options->indata, 60, flags);
    /*
     * (u8 * cFolders) CFFOLDER - structure contains information about
     * one of the folders or partial folders stored in this cabinet file
     */
    nfolders = GET_UINT16_LE(ctx->options->indata + 26);
    while (nfolders) {
        BIO_write(hash, ctx->options->indata + i, 8);
        i += 8;
        nfolders--;
    }
    /* Write what's left - the compressed data bytes */
    len = ctx->cab_ctx->sigpos - i;
    while (len > 0) {
        if (!BIO_write_ex(hash, ctx->options->indata + i, len, &written))
            return 0; /* FAILED */
        len -= written;
        i += written;
    }
    return 1; /* OK */
}

/*
 * Add signed CAB header.
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
 * [returns] 0 on error or 1 on success
 */
static int cab_add_header(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
    size_t i, written, len;
    uint32_t tmp;
    uint16_t nfolders, flags;
    u_char cabsigned[] = {
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0xde, 0xad, 0xbe, 0xef, /* size of cab file */
        0xde, 0xad, 0xbe, 0xef, /* size of asn1 blob */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    char *buf = OPENSSL_malloc(SIZE_64K);
    memset(buf, 0, SIZE_64K);

    /* u1 signature[4] 4643534D MSCF: 0-3 */
    BIO_write(hash, ctx->options->indata, 4);
    /* u4 reserved1 00000000: 4-7 */
    BIO_write(outdata, ctx->options->indata + 4, 4);
    /* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
    tmp = GET_UINT32_LE(ctx->options->indata + 8) + 24;
    PUT_UINT32_LE(tmp, buf);
    BIO_write(hash, buf, 4);
    /* u4 reserved2 00000000: 12-15 */
    BIO_write(hash, ctx->options->indata + 12, 4);
    /* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
    tmp = GET_UINT32_LE(ctx->options->indata + 16) + 24;
    PUT_UINT32_LE(tmp, buf + 4);
    BIO_write(hash, buf + 4, 4);
    /*
     * u4 reserved3 00000000: 20-23
     * u1 versionMinor 03: 24
     * u1 versionMajor 01: 25
     * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
     * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
     */
    memcpy(buf + 4, ctx->options->indata + 20, 10);
    flags = GET_UINT16_LE(ctx->options->indata + 30);
    buf[4+10] = (char)flags | FLAG_RESERVE_PRESENT;
    /* u2 setID must be the same for all cabinets in a set: 32-33 */
    memcpy(buf + 16, ctx->options->indata + 32, 2);
    BIO_write(hash, buf + 4, 14);
    /* u2 iCabinet - number of this cabinet file in a set: 34-35 */
    BIO_write(outdata, ctx->options->indata + 34, 2);
    memcpy(cabsigned + 8, buf, 4);
    BIO_write(outdata, cabsigned, 20);
    BIO_write(hash, cabsigned+20, 4);

    i = cab_write_optional_names(outdata, ctx->options->indata, 36, flags);
    /*
     * (u8 * cFolders) CFFOLDER - structure contains information about
     * one of the folders or partial folders stored in this cabinet file
     */
    nfolders = GET_UINT16_LE(ctx->options->indata + 26);
    while (nfolders) {
        tmp = GET_UINT32_LE(ctx->options->indata + i);
        tmp += 24;
        PUT_UINT32_LE(tmp, buf);
        BIO_write(hash, buf, 4);
        BIO_write(hash, ctx->options->indata + i + 4, 4);
        i += 8;
        nfolders--;
    }
    OPENSSL_free(buf);
    /* Write what's left - the compressed data bytes */
    len = ctx->cab_ctx->fileend - i;
    while (len > 0) {
        if (!BIO_write_ex(hash, ctx->options->indata + i, len, &written))
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
