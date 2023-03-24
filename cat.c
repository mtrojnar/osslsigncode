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
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *cat_ctx_new(GLOBAL_OPTIONS *options, BIO *hash, BIO *outdata);
static PKCS7 *cat_pkcs7_extract(FILE_FORMAT_CTX *ctx);
static PKCS7 *cat_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);
static int cat_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7);
static BIO *cat_bio_free(BIO *hash, BIO *outdata);
static void cat_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata);

FILE_FORMAT file_format_cat = {
	.ctx_new = cat_ctx_new,
	.pkcs7_extract = cat_pkcs7_extract,
	.pkcs7_prepare = cat_pkcs7_prepare,
	.append_pkcs7 = cat_append_pkcs7,
	.bio_free = cat_bio_free,
	.ctx_cleanup = cat_ctx_cleanup,
};

/* Prototypes */
static CAT_CTX *cat_ctx_get(char *indata, uint32_t filesize);

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

	/* squash unused parameter warnings */
	(void)outdata;
	(void)hash;

	if (options->cmd == CMD_REMOVE || options->cmd==CMD_ATTACH) {
		printf("Unsupported command\n");
		return NULL; /* FAILED */
	}
	if (options->cmd == CMD_VERIFY) {
		printf("Use -catalog option\n");
		return NULL; /* FAILED */
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
		printf("Warning: CAT files do not support nesting\n");
	if (options->jp >= 0)
		printf("Warning: -jp option is only valid for CAB files\n");
	if (options->pagehash == 1)
		printf("Warning: -ph option is only valid for PE files\n");
	if (options->add_msi_dse == 1)
		printf("Warning: -add-msi-dse option is only valid for MSI files\n");
	return ctx;
}

/*
 * Extract existing signature to DER or PEM format
 * [in, out] ctx: structure holds input and output data
 * [returns] 1 on error or 0 on success
 */
static PKCS7 *cat_pkcs7_extract(FILE_FORMAT_CTX *ctx)
{
	return pkcs7_get(ctx->options->indata, ctx->cat_ctx->sigpos, ctx->cat_ctx->siglen);
}

/*
 * Obtain an existing signature or create a new one
 * [in, out] ctx: structure holds input and output data
 * [out] hash: message digest BIO (unused)
 * [out] outdata: outdata file BIO (unused)
 * [returns] 1 on error or 0 on success
 */
static PKCS7 *cat_pkcs7_prepare(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
	PKCS7 *cursig = NULL, *p7 = NULL;

	/* squash unused parameter warnings */
	(void)outdata;
	(void)hash;

	/* Obtain an existing signature */
	cursig = pkcs7_get(ctx->options->indata, ctx->cat_ctx->sigpos, ctx->cat_ctx->siglen);
	if (!cursig) {
		printf("Unable to extract existing signature\n");
		return NULL; /* FAILED */
	}
	if (ctx->options->cmd == CMD_ADD || ctx->options->cmd == CMD_ATTACH) {
		p7 = cursig;
	} else if (ctx->options->cmd == CMD_SIGN) {
		/* Create a new signature */
		p7 = pkcs7_create(ctx);
		if (!p7) {
			printf("Creating a new signature failed\n");
			PKCS7_free(cursig);
			return NULL; /* FAILED */
		}
		if (!add_ms_ctl_object(p7, cursig)) {
			printf("Adding MS_CTL_OBJID failed\n");
			PKCS7_free(p7);
			PKCS7_free(cursig);
			return NULL; /* FAILED */
		}
		PKCS7_free(cursig);
	}
	return p7; /* OK */
}

/*
 * Append signature to the outfile
 * [in, out] ctx: structure holds input and output data (unused)
 * [out] outdata: outdata file BIO
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int cat_append_pkcs7(FILE_FORMAT_CTX *ctx, BIO *outdata, PKCS7 *p7)
{
	u_char *p = NULL;
	int len;       /* signature length */

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
 * Free up an entire message digest BIO chain
 * [out] hash: message digest BIO
 * [out] outdata: outdata file BIO
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
 * Deallocate a FILE_FORMAT_CTX structure, unmap indata file, unlink outfile
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void cat_ctx_cleanup(FILE_FORMAT_CTX *ctx, BIO *hash, BIO *outdata)
{
	if (outdata) {
		BIO_free_all(hash);
		if (ctx->options->outfile) {
#ifdef WIN32
			_unlink(ctx->options->outfile);
#else
			unlink(ctx->options->outfile);
#endif /* WIN32 */
		}
	}
	unmap_file(ctx->options->indata, ctx->cat_ctx->fileend);
	OPENSSL_free(ctx->cat_ctx);
	OPENSSL_free(ctx);
}

/*
 * CAT helper functions
 */

/*
 * Verify mapped CAT file TODO and create CAT format specific structures
 * [in] indata: mapped CAT file (unused)
 * [in] filesize: size of CAT file
 * [returns] pointer to CAT format specific structures
 */
static CAT_CTX *cat_ctx_get(char *indata, uint32_t filesize)
{
	CAT_CTX *cat_ctx;

	/* squash the unused parameter warning */
	(void)indata;
	
	cat_ctx = OPENSSL_zalloc(sizeof(CAT_CTX));
	cat_ctx->sigpos = 0;
	cat_ctx->siglen = filesize;
	cat_ctx->fileend = filesize;
	return cat_ctx; /* OK */
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
