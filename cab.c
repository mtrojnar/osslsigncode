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


struct cab_header_st {
	uint32_t header_size;
	uint32_t sigpos;
	uint32_t siglen;
	uint32_t fileend;
	uint16_t flags;
};

/* FILE_FORMAT method prototypes */
static FILE_FORMAT_CTX *cab_ctx_new(GLOBAL_OPTIONS *options);
static ASN1_OBJECT *cab_obsolete_link(FILE_FORMAT_CTX *ctx, u_char **p, int *plen);
static STACK_OF(SIGNATURE) *cab_signature_list_get(FILE_FORMAT_CTX *ctx);
static int cab_verify_digests(FILE_FORMAT_CTX *ctx, SIGNATURE *signature);
static int cab_extract_signature(FILE_FORMAT_CTX *ctx);
static int cab_remove_signature(FILE_FORMAT_CTX *ctx);
static int cab_prepare_signature(FILE_FORMAT_CTX *ctx);
static int cab_append_signature(FILE_FORMAT_CTX *ctx);
static void cab_update_data_size(FILE_FORMAT_CTX *ctx);
static void cab_ctx_free(FILE_FORMAT_CTX *ctx);
static void cab_ctx_cleanup(FILE_FORMAT_CTX *ctx);

FILE_FORMAT file_format_cab = {
	.ctx_new = cab_ctx_new,
	.get_data_blob = cab_obsolete_link,
	.signature_list_get = cab_signature_list_get,
	.verify_digests = cab_verify_digests,
	.extract_signature = cab_extract_signature,
	.remove_signature = cab_remove_signature,
	.prepare_signature = cab_prepare_signature,
	.append_signature = cab_append_signature,
	.update_data_size = cab_update_data_size,
	.ctx_free = cab_ctx_free,
	.ctx_cleanup = cab_ctx_cleanup
};

/* Prototypes */
static int cab_verify_header(char *indata, uint32_t filesize, CAB_HEADER *header);
static PKCS7 *cab_get_sigfile(FILE_FORMAT_CTX *ctx);
static PKCS7 *cab_create_signature(FILE_FORMAT_CTX *ctx);
static void cab_add_jp_attribute(PKCS7_SIGNER_INFO *si, int jp);
static PKCS7 *cab_extract_existing_pkcs7(char *indata, CAB_HEADER *header);
static void cab_optional_names(uint16_t flags, char *indata, BIO *outdata, size_t *len);
static int cab_modify_header(FILE_FORMAT_CTX *ctx);
static int cab_add_header(FILE_FORMAT_CTX *ctx);
static int cab_calc_digest(char *indata, int mdtype, u_char *mdbuf, CAB_HEADER *header);


/*
 * FILE_FORMAT method definitions
 */

/*
 * Allocate and return a CAB file format context.
 * [in, out] options: structure holds the input data
 * [returns] pointer to CAB file format context
 */
static FILE_FORMAT_CTX *cab_ctx_new(GLOBAL_OPTIONS *options)
{
	FILE_FORMAT_CTX *ctx;
	CAB_HEADER *header;
	SIGN_DATA *sign;
	BIO *hash, *outdata = NULL;
	uint32_t filesize;

	if (options->pagehash == 1)
		printf("Warning: -ph option is only valid for PE files\n");
	if (options->add_msi_dse == 1)
		printf("Warning: -add-msi-dse option is only valid for MSI files\n");

	filesize = get_file_size(options->infile);
	if (filesize == 0)
		return NULL; /* FAILED */

	options->indata = map_file(options->infile, filesize);
	if (!options->indata) {
		return NULL; /* FAILED */
	}
	if (memcmp(options->indata, "MSCF", 4)) {
		unmap_file(options->infile, filesize);
		return NULL; /* FAILED */
	}
	header = OPENSSL_zalloc(sizeof(CAB_HEADER));
	if (!cab_verify_header(options->indata, filesize, header)) {
		unmap_file(options->infile, filesize);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	hash = BIO_new(BIO_f_md());
	if (!BIO_set_md(hash, options->md)) {
		printf("Unable to set the message digest of BIO\n");
		unmap_file(options->infile, filesize);
		BIO_free_all(hash);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	if (options->cmd != CMD_VERIFY) {
		/* Create outdata file */
		outdata = BIO_new_file(options->outfile, FILE_CREATE_MODE);
		if (outdata == NULL) {
			printf("Failed to create file: %s\n", options->outfile);
			unmap_file(options->infile, filesize);
			BIO_free_all(hash);
			OPENSSL_free(header);
			return NULL; /* FAILED */
		}
		BIO_push(hash, outdata);
	}
	sign = OPENSSL_malloc(sizeof(SIGN_DATA));
	sign->outdata = outdata;
	sign->hash = hash;
	sign->sig = sign->cursig = NULL;
	sign->len = sign->padlen = 0;

	ctx = OPENSSL_malloc(sizeof(FILE_FORMAT_CTX));
	ctx->format = &file_format_cab;
	ctx->options = options;
	ctx->sign = sign;
	ctx->cab = header;
	return ctx;
}

/*
 * Allocate and return SpcLink object.
 * [in] ctx: structure holds all input and output data (unused)
 * [out] p: SpcLink data
 * [out] plen: SpcLink data length
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_CAB_DATA_OBJID
 */
static ASN1_OBJECT *cab_obsolete_link(FILE_FORMAT_CTX *ctx, u_char **p, int *plen)
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
 * Retrieve all PKCS#7 (include nested) signedData structures from CAB file,
 * allocate and return signature list
 * [in, out] ctx: structure holds all input and output data
 * [returns] pointer to signature list
 */
static STACK_OF(SIGNATURE) *cab_signature_list_get(FILE_FORMAT_CTX *ctx)
{
	PKCS7 *p7;
	STACK_OF(SIGNATURE) *signatures;

	if (!ctx) {
		printf("Init error\n\n");
		return NULL; /* FAILED */
	}
	if (ctx->cab->header_size != 20) {
		printf("No signature found\n\n");
		return NULL; /* FAILED */
	}
	if (ctx->cab->sigpos == 0 || ctx->cab->siglen == 0
		|| ctx->cab->sigpos > ctx->cab->fileend) {
		printf("No signature found\n\n");
		return NULL; /* FAILED */
	}
	p7 = cab_extract_existing_pkcs7(ctx->options->indata, ctx->cab);
	if (!p7) {
		printf("Failed to extract PKCS7 data\n\n");
		return NULL; /* FAILED */
	}
	signatures = sk_SIGNATURE_new_null();
	if (!signature_list_append_pkcs7(&signatures, p7, 1)) {
		printf("Failed to create signature list\n\n");
		PKCS7_free(p7);
		return NULL; /* FAILED */
	}
	return signatures;
}

/*
 * Calculate message digest and compare to value retrieved from PKCS#7 signedData
 * [in] ctx: structure holds all input and output data
 * [in] signature: structure for authenticode and time stamping
 * [returns] 0 on error or 1 on success
 */
static int cab_verify_digests(FILE_FORMAT_CTX *ctx, SIGNATURE *signature)
{
	int mdtype = -1;
	u_char mdbuf[EVP_MAX_MD_SIZE];
	u_char cmdbuf[EVP_MAX_MD_SIZE];

	if (is_content_type(signature->p7, SPC_INDIRECT_DATA_OBJID)) {
		ASN1_STRING *content_val = signature->p7->d.sign->contents->d.other->value.sequence;
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
	if (!cab_calc_digest(ctx->options->indata, mdtype, cmdbuf, ctx->cab)) {
		printf("Failed to calculate message digest\n\n");
		return 0; /* FAILED */
	}
	if (!compare_digests(mdbuf, cmdbuf, mdtype)) {
		printf("Signature verification: failed\n\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

/*
 * Extract existing signature to DER or PEM format
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int cab_extract_signature(FILE_FORMAT_CTX *ctx)
{
	int ret = 0;
	PKCS7 *sig;
	size_t written;

	(void)BIO_reset(ctx->sign->outdata);
	if (ctx->options->output_pkcs7) {
		sig = cab_extract_existing_pkcs7(ctx->options->indata, ctx->cab);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(ctx->sign->outdata, sig);
		PKCS7_free(sig);
	} else
		if (!BIO_write_ex(ctx->sign->outdata,
			ctx->options->indata + ctx->cab->sigpos,
			ctx->cab->siglen, &written) || written != ctx->cab->siglen)
			ret = 1; /* FAILED */
	return ret;
}

/*
 * Remove existing signature
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int cab_remove_signature(FILE_FORMAT_CTX *ctx)
{
	size_t i, written, len;
	uint32_t tmp;
	uint16_t nfolders, flags;
	char *buf = OPENSSL_malloc(SIZE_64K);

	/*
	 * u1 signature[4] 4643534D MSCF: 0-3
	 * u4 reserved1 00000000: 4-7
	 */
	BIO_write(ctx->sign->outdata, ctx->options->indata, 8);
	/* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
	tmp = GET_UINT32_LE(ctx->options->indata + 8) - 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(ctx->sign->outdata, buf, 4);
	/* u4 reserved2 00000000: 12-15 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 12, 4);
	/* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	tmp = GET_UINT32_LE(ctx->options->indata + 16) - 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(ctx->sign->outdata, buf, 4);
	/*
	 * u4 reserved3 00000000: 20-23
	 * u1 versionMinor 03: 24
	 * u1 versionMajor 01: 25
	 * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
	 * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
	 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 20, 10);
	/* u2 flags: 30-31 */
	flags = GET_UINT16_LE(ctx->options->indata + 30);
	/* coverity[result_independent_of_operands] only least significant byte is affected */
	PUT_UINT16_LE(flags & (FLAG_PREV_CABINET | FLAG_NEXT_CABINET), buf);
	BIO_write(ctx->sign->outdata, buf, 2);
	/*
	 * u2 setID must be the same for all cabinets in a set: 32-33
	 * u2 iCabinet - number of this cabinet file in a set: 34-35
	 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 32, 4);
	i = 60;
	cab_optional_names(flags, ctx->options->indata, ctx->sign->outdata, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(ctx->options->indata + 26);
	while (nfolders) {
		tmp = GET_UINT32_LE(ctx->options->indata + i);
		tmp -= 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(ctx->sign->outdata, buf, 4);
		BIO_write(ctx->sign->outdata, ctx->options->indata + i + 4, 4);
		i+=8;
		nfolders--;
	}
	OPENSSL_free(buf);
	/* Write what's left - the compressed data bytes */
	len = ctx->cab->fileend - ctx->cab->siglen - i;
	while (len > 0) {
		if (!BIO_write_ex(ctx->sign->outdata, ctx->options->indata + i, len, &written))
			return 1; /* FAILED */
		len -= written;
		i += written;
	}
	return 0; /* OK */
}

/*
 * Obtain an existing signature or create a new one
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int cab_prepare_signature(FILE_FORMAT_CTX *ctx)
{
	PKCS7 *sig = NULL;

	/* Obtain a current signature from previously-signed file */
	if ((ctx->options->cmd == CMD_SIGN && ctx->options->nest)
		|| (ctx->options->cmd == CMD_ATTACH && ctx->options->nest)
		|| ctx->options->cmd == CMD_ADD) {
		ctx->sign->cursig = cab_extract_existing_pkcs7(ctx->options->indata, ctx->cab);
		if (!ctx->sign->cursig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		if (ctx->options->cmd == CMD_ADD)
			sig = ctx->sign->cursig;
	}
	if (ctx->cab->header_size == 20) {
		/* Strip current signature and modify header */
		if (!cab_modify_header(ctx))
			return 1; /* FAILED */
	} else {
		if (!cab_add_header(ctx))
			return 1; /* FAILED */
	}
	if (ctx->options->cmd == CMD_ATTACH) {
		/* Obtain an existing signature */
		sig = cab_get_sigfile(ctx);
		if (!sig) {
			printf("Unable to extract valid signature\n");
			return 1; /* FAILED */
		}
	} else if (ctx->options->cmd == CMD_SIGN) {
		/* Create a new signature */
		sig = cab_create_signature(ctx);
		if (!sig) {
			printf("Creating a new signature failed\n");
			return 1; /* FAILED */
		}
	}
	ctx->sign->sig = sig;
	return 0; /* OK */
}

/*
 * Append signature to the outfile
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int cab_append_signature(FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	PKCS7 *outsig;

	if (ctx->options->nest) {
		if (ctx->sign->cursig == NULL) {
			printf("Internal error: No 'cursig' was extracted\n");
			return 1; /* FAILED */
		}
		if (set_nested_signature(ctx) == 0) {
			printf("Unable to append the nested signature to the current signature\n");
			return 1; /* FAILED */
		}
		outsig = ctx->sign->cursig;
	} else {
		outsig = ctx->sign->sig;
	}
	/* Append signature to the outfile */
	if (((ctx->sign->len = i2d_PKCS7(outsig, NULL)) <= 0)
		|| (p = OPENSSL_malloc((size_t)ctx->sign->len)) == NULL) {
		printf("i2d_PKCS memory allocation failed: %d\n", ctx->sign->len);
		return 1; /* FAILED */
	}
	i2d_PKCS7(outsig, &p);
	p -= ctx->sign->len;
	ctx->sign->padlen = (8 - ctx->sign->len % 8) % 8;
	BIO_write(ctx->sign->outdata, p, ctx->sign->len);
	/* pad (with 0's) asn1 blob to 8 byte boundary */
	if (ctx->sign->padlen > 0) {
		memset(p, 0, (size_t)ctx->sign->padlen);
		BIO_write(ctx->sign->outdata, p, ctx->sign->padlen);
	}
	OPENSSL_free(p);
	return 0; /* OK */
}

/*
 * Update additional data size.
 * Additional data size is located at offset 0x30 (from file beginning)
 * and consist of 4 bytes (little-endian order).
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void cab_update_data_size(FILE_FORMAT_CTX *ctx)
{
	u_char buf[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (ctx->options->cmd == CMD_VERIFY || ctx->options->cmd == CMD_EXTRACT
		|| ctx->options->cmd == CMD_REMOVE) {
		return;
	}
	(void)BIO_seek(ctx->sign->outdata, 0x30);
	PUT_UINT32_LE(ctx->sign->len + ctx->sign->padlen, buf);
	BIO_write(ctx->sign->outdata, buf, 4);
}

/*
 * Free up an entire hash BIO chain
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void cab_ctx_free(FILE_FORMAT_CTX *ctx)
{
	BIO_free_all(ctx->sign->hash);
	ctx->sign->hash = ctx->sign->outdata = NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure, unmap indata file, unlink outfile
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void cab_ctx_cleanup(FILE_FORMAT_CTX *ctx)
{
	if (ctx->sign->hash) {
		BIO_free_all(ctx->sign->hash);
	}
	if (ctx->sign->outdata) {
		if (ctx->options->outfile) {
#ifdef WIN32
			_unlink(ctx->options->outfile);
#else
			unlink(ctx->options->outfile);
#endif /* WIN32 */
		}
	}
	unmap_file(ctx->options->indata, ctx->cab->fileend);
	PKCS7_free(ctx->sign->sig);
	if (ctx->options->cmd != CMD_ADD)
		PKCS7_free(ctx->sign->cursig);
	OPENSSL_free(ctx->sign);
	OPENSSL_free(ctx->cab);
	OPENSSL_free(ctx);
}

/*
 * CAB helper functions
 */
static int cab_verify_header(char *indata, uint32_t filesize, CAB_HEADER *header)
{
	uint32_t reserved;

	if (filesize < 44) {
		printf("CAB file is too short\n");
		return 0; /* FAILED */
	}
	header->fileend = filesize;
	reserved = GET_UINT32_LE(indata + 4);
	if (reserved) {
		printf("Reserved1: 0x%08X\n", reserved);
		return 0; /* FAILED */
	}
	/* flags specify bit-mapped values that indicate the presence of optional data */
	header->flags = GET_UINT16_LE(indata + 30);
	if (header->flags & FLAG_PREV_CABINET) {
		/* FLAG_NEXT_CABINET works */
		printf("Multivolume cabinet file is unsupported: flags 0x%04X\n", header->flags);
		return 0; /* FAILED */
	}
	if (header->flags & FLAG_RESERVE_PRESENT) {
		/*
		* Additional headers is located at offset 36 (cbCFHeader, cbCFFolder, cbCFData);
		* size of header (4 bytes, little-endian order) must be 20 (checkpoint).
		*/
		header->header_size = GET_UINT32_LE(indata + 36);
		if (header->header_size != 20) {
			printf("Additional header size: 0x%08X\n", header->header_size);
			return 0; /* FAILED */
		}
		reserved = GET_UINT32_LE(indata + 40);
		if (reserved != 0x00100000) {
			printf("abReserved: 0x%08X\n", reserved);
			return 0; /* FAILED */
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
		header->sigpos = GET_UINT32_LE(indata + 44);
		header->siglen = GET_UINT32_LE(indata + 48);
		if ((header->sigpos < filesize && header->sigpos + header->siglen != filesize)
			|| (header->sigpos >= filesize)) {
			printf("Additional data offset:\t%u bytes\nAdditional data size:\t%u bytes\n",
				header->sigpos, header->siglen);
			printf("File size:\t\t%u bytes\n", filesize);
			return 0; /* FAILED */
		}
		if ((header->sigpos > 0 && header->siglen == 0) || (header->sigpos == 0 && header->siglen > 0)) {
			printf("Corrupt signature\n");
			return 0; /* FAILED */
		}
	}
	return 1; /* OK */
}

static PKCS7 *cab_get_sigfile(FILE_FORMAT_CTX *ctx)
{
	PKCS7 *sig = NULL;
	uint32_t sigfilesize;
	char *insigdata;
	CAB_HEADER header;
	BIO *sigbio;
	const char pemhdr[] = "-----BEGIN PKCS7-----";

	sigfilesize = get_file_size(ctx->options->sigfile);
	if (!sigfilesize) {
		return NULL; /* FAILED */
	}
	insigdata = map_file(ctx->options->sigfile, sigfilesize);
	if (!insigdata) {
		printf("Failed to open file: %s\n", ctx->options->sigfile);
		return NULL; /* FAILED */
	}
	if (sigfilesize >= sizeof pemhdr && !memcmp(insigdata, pemhdr, sizeof pemhdr - 1)) {
		sigbio = BIO_new_mem_buf(insigdata, (int)sigfilesize);
		sig = PEM_read_bio_PKCS7(sigbio, NULL, NULL, NULL);
		BIO_free_all(sigbio);
	} else {
		/* reset header */
		memset(&header, 0, sizeof(CAB_HEADER));
		header.fileend = sigfilesize;
		header.siglen = sigfilesize;
		header.sigpos = 0;
		sig = cab_extract_existing_pkcs7(insigdata, &header);
	}
	unmap_file(insigdata, sigfilesize);
	return sig; /* OK */
}

static PKCS7 *cab_create_signature(FILE_FORMAT_CTX *ctx)
{
	int i, signer = -1;
	PKCS7 *sig;
	PKCS7_SIGNER_INFO *si = NULL;

	sig = PKCS7_new();
	PKCS7_set_type(sig, NID_pkcs7_signed);

	if (ctx->options->cert != NULL) {
		/*
		 * the private key and corresponding certificate are parsed from the PKCS12
		 * structure or loaded from the security token, so we may omit to check
		 * the consistency of a private key with the public key in an X509 certificate
		 */
		si = PKCS7_add_signature(sig, ctx->options->cert, ctx->options->pkey, ctx->options->md);
		if (si == NULL)
			return NULL; /* FAILED */
	} else {
		/* find the signer's certificate located somewhere in the whole certificate chain */
		for (i=0; i<sk_X509_num(ctx->options->certs); i++) {
			X509 *signcert = sk_X509_value(ctx->options->certs, i);
			if (X509_check_private_key(signcert, ctx->options->pkey)) {
				si = PKCS7_add_signature(sig, signcert, ctx->options->pkey, ctx->options->md);
				signer = i;
				break;
			}
		}
		if (si == NULL) {
			printf("Failed to checking the consistency of a private key: %s\n",
				ctx->options->keyfile);
			printf("          with a public key in any X509 certificate: %s\n\n",
				ctx->options->certfile);
			return NULL; /* FAILED */
		}
	}
	pkcs7_signer_info_add_signing_time(si, ctx);
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
		V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1));

	if (ctx->options->jp >= 0)
		cab_add_jp_attribute(si, ctx->options->jp);

	if (!pkcs7_signer_info_add_purpose(si, ctx))
		return NULL; /* FAILED */

	if ((ctx->options->desc || ctx->options->url) &&
			!pkcs7_signer_info_add_spc_sp_opus_info(si, ctx)) {
		printf("Couldn't allocate memory for opus info\n");
		return NULL; /* FAILED */
	}
	PKCS7_content_new(sig, NID_pkcs7_data);

	/* add the signer's certificate */
	if (ctx->options->cert != NULL)
		PKCS7_add_certificate(sig, ctx->options->cert);
	if (signer != -1)
		PKCS7_add_certificate(sig, sk_X509_value(ctx->options->certs, signer));

	/* add the certificate chain */
	for (i=0; i<sk_X509_num(ctx->options->certs); i++) {
		if (i == signer)
			continue;
		PKCS7_add_certificate(sig, sk_X509_value(ctx->options->certs, i));
	}
	/* add all cross certificates */
	if (ctx->options->xcerts) {
		for (i=0; i<sk_X509_num(ctx->options->xcerts); i++)
			PKCS7_add_certificate(sig, sk_X509_value(ctx->options->xcerts, i));
	}
	/* add crls */
	if (ctx->options->crls) {
		for (i=0; i<sk_X509_CRL_num(ctx->options->crls); i++)
			PKCS7_add_crl(sig, sk_X509_CRL_value(ctx->options->crls, i));
	}
	if (!pkcs7_set_data_content(sig, ctx)) {
		PKCS7_free(sig);
		printf("Signing failed\n");
		return NULL; /* FAILED */
	}
	return sig; /* OK */
}

/* Compute a message digest value of the signed or unsigned CAB file */
static int cab_calc_digest(char *indata, int mdtype, u_char *mdbuf, CAB_HEADER *header)
{
	uint32_t idx, fileend, coffFiles;
	const EVP_MD *md = EVP_get_digestbynid(mdtype);
	BIO *bhash = BIO_new(BIO_f_md());

	if (!BIO_set_md(bhash, md)) {
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return 0;  /* FAILED */
	}
	BIO_push(bhash, BIO_new(BIO_s_null()));

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_write(bhash, indata, 4);
	/* u4 reserved1 00000000: 4-7 skipped */
	if (header->sigpos) {
		uint16_t nfolders, flags;
		
		/*
		 * u4 cbCabinet - size of this cabinet file in bytes: 8-11
		 * u4 reserved2 00000000: 12-15
		 */
		BIO_write(bhash, indata + 8, 8);
		 /* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
		coffFiles = GET_UINT32_LE(indata + 16);
		BIO_write(bhash, indata + 16, 4);
		/*
		 * u4 reserved3 00000000: 20-23
		 * u1 versionMinor 03: 24
		 * u1 versionMajor 01: 25
		 */
		BIO_write(bhash, indata + 20, 6);
		/* u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27 */
		nfolders = GET_UINT16_LE(indata + 26);
		BIO_write(bhash, indata + 26, 2);
		/* u2 cFiles - number of CFFILE entries in this cabinet: 28-29 */
		BIO_write(bhash, indata + 28, 2);
		/* u2 flags: 30-31 */
		flags = GET_UINT16_LE(indata + 30);
		BIO_write(bhash, indata + 30, 2);
		/* u2 setID must be the same for all cabinets in a set: 32-33 */
		BIO_write(bhash, indata + 32, 2);
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
		BIO_write(bhash, indata + 56, 4);
		idx = 60;
		fileend = header->sigpos;
		/* TODO */
		if (flags & FLAG_PREV_CABINET) {
			uint8_t byte;
			/* szCabinetPrev */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				idx++;
			} while (byte && idx < fileend);
			/* szDiskPrev */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				idx++;
			} while (byte && idx < fileend);
		}
		if (flags & FLAG_NEXT_CABINET) {
			uint8_t byte;
			/* szCabinetNext */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				idx++;
			} while (byte && idx < fileend);
			/* szDiskNext */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				idx++;
			} while (byte && idx < fileend);
		}
		/*
		 * (u8 * cFolders) CFFOLDER - structure contains information about
		 * one of the folders or partial folders stored in this cabinet file
		 */
		while (nfolders) {
			BIO_write(bhash, indata + idx, 8);
			idx += 8;
			nfolders--;
		}
		if (idx != coffFiles) {
			printf("Corrupt coffFiles value: 0x%08X\n", coffFiles);
			BIO_free_all(bhash);
			return 0;  /* FAILED */
		}
	} else {
		/* TESTME with CAT file */
		/* read what's left of the unsigned CAB file */
		idx = 8;
		fileend = header->fileend;
	}
	/* (variable) ab - the compressed data bytes */
	if (!bio_hash_data(bhash, indata, idx, fileend)) {
		printf("Unable to calculate digest\n");
		BIO_free_all(bhash);
		return 0;  /* FAILED */
	}
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);
	return 1; /* OK */
}

static PKCS7 *cab_extract_existing_pkcs7(char *indata, CAB_HEADER *header)
{
	PKCS7 *p7 = NULL;
	const u_char *blob;

	blob = (u_char *)indata + header->sigpos;
	p7 = d2i_PKCS7(NULL, &blob, header->siglen);
	return p7;
}

static void cab_add_jp_attribute(PKCS7_SIGNER_INFO *si, int jp)
{
	ASN1_STRING *astr;
	const u_char *attrs = NULL;
	const u_char java_attrs_low[] = {
		0x30, 0x06, 0x03, 0x02, 0x00, 0x01, 0x30, 0x00
	};

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
		PKCS7_add_signed_attribute(si, OBJ_txt2nid(MS_JAVA_SOMETHING),
				V_ASN1_SEQUENCE, astr);
	}
}

static void cab_optional_names(uint16_t flags, char *indata, BIO *outdata, size_t *len)
{
	size_t i = *len;

	/* TODO */
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
	*len = i;
}

static int cab_modify_header(FILE_FORMAT_CTX *ctx)
{
	size_t i, written, len;
	uint16_t nfolders, flags;
	u_char buf[] = {0x00, 0x00};

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_write(ctx->sign->hash, ctx->options->indata, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 4, 4);
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
	BIO_write(ctx->sign->hash, ctx->options->indata + 8, 22);
	/* u2 flags: 30-31 */
	flags = GET_UINT16_LE(ctx->options->indata + 30);
	PUT_UINT16_LE(flags, buf);
	BIO_write(ctx->sign->hash, buf, 2);
	/* u2 setID must be the same for all cabinets in a set: 32-33 */
	BIO_write(ctx->sign->hash, ctx->options->indata + 32, 2);
	/*
	 * u2 iCabinet - number of this cabinet file in a set: 34-35
	 * u2 cbCFHeader: 36-37
	 * u1 cbCFFolder: 38
	 * u1 cbCFData: 39
	 * u16 abReserve: 40-55
	 * - Additional data offset: 44-47
	 * - Additional data size: 48-51
	 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 34, 22);
	/* u4 abReserve: 56-59 */
	BIO_write(ctx->sign->hash, ctx->options->indata + 56, 4);

	i = 60;
	cab_optional_names(flags, ctx->options->indata, ctx->sign->hash, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(ctx->options->indata + 26);
	while (nfolders) {
		BIO_write(ctx->sign->hash, ctx->options->indata + i, 8);
		i += 8;
		nfolders--;
	}
	/* Write what's left - the compressed data bytes */
	len = ctx->cab->sigpos - i;
	while (len > 0) {
		if (!BIO_write_ex(ctx->sign->hash, ctx->options->indata + i, len, &written))
			return 0; /* FAILED */
		len -= written;
		i += written;
	}
	return 1; /* OK */
}

static int cab_add_header(FILE_FORMAT_CTX *ctx)
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
	BIO_write(ctx->sign->hash, ctx->options->indata, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 4, 4);
	/* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
	tmp = GET_UINT32_LE(ctx->options->indata + 8) + 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(ctx->sign->hash, buf, 4);
	/* u4 reserved2 00000000: 12-15 */
	BIO_write(ctx->sign->hash, ctx->options->indata + 12, 4);
	/* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	tmp = GET_UINT32_LE(ctx->options->indata + 16) + 24;
	PUT_UINT32_LE(tmp, buf + 4);
	BIO_write(ctx->sign->hash, buf + 4, 4);
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
	BIO_write(ctx->sign->hash, buf + 4, 14);
	/* u2 iCabinet - number of this cabinet file in a set: 34-35 */
	BIO_write(ctx->sign->outdata, ctx->options->indata + 34, 2);
	memcpy(cabsigned + 8, buf, 4);
	BIO_write(ctx->sign->outdata, cabsigned, 20);
	BIO_write(ctx->sign->hash, cabsigned+20, 4);

	i = 36;
	cab_optional_names(flags, ctx->options->indata, ctx->sign->hash, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(ctx->options->indata + 26);
	while (nfolders) {
		tmp += 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(ctx->sign->hash, buf, 4);
		BIO_write(ctx->sign->hash, ctx->options->indata + i + 4, 4);
		i += 8;
		nfolders--;
	}
	OPENSSL_free(buf);
	/* Write what's left - the compressed data bytes */
	len = ctx->cab->fileend - i;
	while (len > 0) {
		if (!BIO_write_ex(ctx->sign->hash, ctx->options->indata + i, len, &written))
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
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
