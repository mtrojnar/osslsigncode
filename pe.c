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

struct pe_header_st {
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
static FILE_FORMAT_CTX *pe_ctx_new(GLOBAL_OPTIONS *options);
static ASN1_OBJECT *pe_spc_image_data(FILE_FORMAT_CTX *ctx, u_char **p, int *plen);
static STACK_OF(SIGNATURE) *pe_signature_list_get(FILE_FORMAT_CTX *ctx);
static int pe_verify_digests(FILE_FORMAT_CTX *ctx, SIGNATURE *signature);
static int pe_extract_signature(FILE_FORMAT_CTX *ctx);
static int pe_remove_signature(FILE_FORMAT_CTX *ctx);
static int pe_prepare_signature(FILE_FORMAT_CTX *ctx);
static int pe_append_signature(FILE_FORMAT_CTX *ctx);
static void pe_update_data_size(FILE_FORMAT_CTX *ctx);
static void pe_ctx_free(FILE_FORMAT_CTX *ctx);
static void pe_ctx_cleanup(FILE_FORMAT_CTX *ctx);

FILE_FORMAT file_format_pe = {
	.ctx_new = pe_ctx_new,
	.get_data_blob = pe_spc_image_data,
	.signature_list_get = pe_signature_list_get,
	.verify_digests = pe_verify_digests,
	.extract_signature = pe_extract_signature,
	.remove_signature = pe_remove_signature,
	.prepare_signature = pe_prepare_signature,
	.append_signature = pe_append_signature,
	.update_data_size = pe_update_data_size,
	.ctx_free = pe_ctx_free,
	.ctx_cleanup = pe_ctx_cleanup
};

/* Prototypes */
static int pe_verify_header(char *indata, uint32_t filesize, PE_HEADER *header);
static uint32_t pe_calc_checksum(BIO *bio, PE_HEADER *header);
static uint32_t pe_calc_realchecksum(FILE_FORMAT_CTX *ctx);
static PKCS7 *pe_get_sigfile(FILE_FORMAT_CTX *ctx);
static PKCS7 *pe_create_signature(FILE_FORMAT_CTX *ctx);
static int pe_modify_header(FILE_FORMAT_CTX *ctx);
static PKCS7 *pe_extract_existing_pkcs7(char *indata, PE_HEADER *header);
static SpcLink *get_page_hash_link(FILE_FORMAT_CTX *ctx, int phtype);
static int pe_calc_digest(char *indata, int mdtype, u_char *mdbuf, PE_HEADER *header);
static int pe_extract_page_hash(SpcAttributeTypeAndOptionalValue *obj,
	u_char **ph, int *phlen, int *phtype);
static int pe_compare_page_hash(FILE_FORMAT_CTX *ctx, u_char *ph, int phlen, int phtype);


/*
 * FILE_FORMAT method definitions
 */

/*
 * Allocate and return a PE file format context.
 * [in, out] options: structure holds the input data
 * [returns] pointer to PE file format context
 */
static FILE_FORMAT_CTX *pe_ctx_new(GLOBAL_OPTIONS *options)
{
	FILE_FORMAT_CTX *ctx;
	PE_HEADER *header;
	SIGN_DATA *sign;
	BIO *hash, *outdata = NULL;
	uint32_t filesize;
	
	if (options->jp >= 0)
		printf("Warning: -jp option is only valid for CAB files\n");
	if (options->add_msi_dse == 1)
		printf("Warning: -add-msi-dse option is only valid for MSI files\n");

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
	header = OPENSSL_zalloc(sizeof(PE_HEADER));
	if (!pe_verify_header(options->indata, filesize, header)) {
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
	ctx->format = &file_format_pe;
	ctx->options = options;
	ctx->sign = sign;
	ctx->pe = header;
	return ctx;
}

/*
 * Allocate and return SpcPeImageData object.
 * [in] ctx: structure holds all input and output data
 * [out] p: SpcPeImageData data
 * [out] plen: SpcPeImageData data length
 * [returns] pointer to ASN1_OBJECT structure corresponding to SPC_PE_IMAGE_DATA_OBJID
 */
static ASN1_OBJECT *pe_spc_image_data(FILE_FORMAT_CTX *ctx, u_char **p, int *plen)
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
		link = get_page_hash_link(ctx, phtype);
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
 * Retrieve all PKCS#7 (include nested) signedData structures from PE file,
 * allocate and return signature list
 * [in, out] ctx: structure holds all input and output data
 * [returns] pointer to signature list
 */
static STACK_OF(SIGNATURE) *pe_signature_list_get(FILE_FORMAT_CTX *ctx)
{
	int peok = 1;
	uint32_t real_pe_checksum;
	PKCS7 *p7;
	STACK_OF(SIGNATURE) *signatures;

	if (!ctx) {
		printf("Init error\n\n");
		return NULL; /* FAILED */
	}
	if (ctx->pe->siglen == 0)
		ctx->pe->sigpos = ctx->pe->fileend;

	/* check PE checksum */
	printf("Current PE checksum   : %08X\n", ctx->pe->pe_checksum);
	real_pe_checksum = pe_calc_realchecksum(ctx);
	if (ctx->pe->pe_checksum && ctx->pe->pe_checksum != real_pe_checksum)
		peok = 0;
	printf("Calculated PE checksum: %08X%s\n\n", real_pe_checksum, peok ? "" : "    MISMATCH!!!");

	if (ctx->pe->sigpos == 0 || ctx->pe->siglen == 0
		|| ctx->pe->sigpos > ctx->pe->fileend) {
		printf("No signature found\n\n");
		return NULL; /* FAILED */
	}
	if (ctx->pe->siglen != GET_UINT32_LE(ctx->options->indata + ctx->pe->sigpos)) {
		printf("Invalid signature\n\n");
		return NULL; /* FAILED */
	}
	p7 = pe_extract_existing_pkcs7(ctx->options->indata, ctx->pe);
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
 * Calculate message digest and page_hash, compare to values retrieved from PKCS#7 signedData
 * [in] ctx: structure holds all input and output data
 * [in] signature: structure for authenticode and time stamping
 * [returns] 0 on error or 1 on success
 */
static int pe_verify_digests(FILE_FORMAT_CTX *ctx, SIGNATURE *signature)
{
	int mdtype = -1, phtype = -1;
	u_char mdbuf[EVP_MAX_MD_SIZE];
	u_char cmdbuf[EVP_MAX_MD_SIZE];
	u_char *ph = NULL;
	int phlen = 0;

	if (is_content_type(signature->p7, SPC_INDIRECT_DATA_OBJID)) {
		ASN1_STRING *content_val = signature->p7->d.sign->contents->d.other->value.sequence;
		const u_char *p = content_val->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, content_val->length);
		if (idc) {
			if (!pe_extract_page_hash(idc->data, &ph, &phlen, &phtype)) {
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
	if (!pe_calc_digest(ctx->options->indata, mdtype, cmdbuf, ctx->pe)) {
		printf("Failed to calculate message digest\n\n");
		OPENSSL_free(ph);
		return 0; /* FAILED */
	}
	if (!compare_digests(mdbuf, cmdbuf, mdtype)) {
		printf("Signature verification: failed\n\n");
		OPENSSL_free(ph);
		return 0; /* FAILED */
	}
	if (phlen > 0 && !pe_compare_page_hash(ctx, ph, phlen, phtype)) {
		printf("Signature verification: failed\n\n");
		OPENSSL_free(ph);
		return 0; /* FAILED */
	}
	OPENSSL_free(ph);
	return 1; /* OK */
}

/*
 * Extract existing signature to DER or PEM format
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int pe_extract_signature(FILE_FORMAT_CTX *ctx)
{
	int ret = 0;
	PKCS7 *sig;
	size_t written;

	if (ctx->pe->sigpos == 0) {
		printf("PE file does not have any signature\n");
		return 1; /* FAILED */
	}
	(void)BIO_reset(ctx->sign->outdata);
	if (ctx->options->output_pkcs7) {
		sig = pe_extract_existing_pkcs7(ctx->options->indata, ctx->pe);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(ctx->sign->outdata, sig);
		PKCS7_free(sig);
	} else
		if (!BIO_write_ex(ctx->sign->outdata,
			ctx->options->indata + ctx->pe->sigpos,
			ctx->pe->siglen, &written) || written != ctx->pe->siglen)
			ret = 1; /* FAILED */
	return ret;
}

/*
 * Remove existing signature
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int pe_remove_signature(FILE_FORMAT_CTX *ctx)
{
	if (ctx->pe->sigpos == 0) {
		printf("PE file does not have any signature\n");
		return 1; /* FAILED */
	}
	return pe_prepare_signature(ctx);
}

/*
 * Obtain an existing signature or create a new one
 * [in, out] ctx: structure holds all input and output data
 * [returns] 1 on error or 0 on success
 */
static int pe_prepare_signature(FILE_FORMAT_CTX *ctx)
{
	PKCS7 *sig = NULL;

	/* Obtain a current signature from previously-signed file */
	if ((ctx->options->cmd == CMD_SIGN && ctx->options->nest)
		|| (ctx->options->cmd == CMD_ATTACH && ctx->options->nest)
		|| ctx->options->cmd == CMD_ADD) {
		ctx->sign->cursig = pe_extract_existing_pkcs7(ctx->options->indata, ctx->pe);
		if (!ctx->sign->cursig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		if (ctx->options->cmd == CMD_ADD)
			sig = ctx->sign->cursig;
	}
	if (ctx->pe->sigpos > 0) {
		/* Strip current signature */
		ctx->pe->fileend = ctx->pe->sigpos;
	}
	if (!pe_modify_header(ctx)) {
		printf("Unable to modify file header\n");
		return 1; /* FAILED */
	}
	if (ctx->options->cmd == CMD_ATTACH) {
		/* Obtain an existing signature */
		sig = pe_get_sigfile(ctx);
		if (!sig) {
			printf("Unable to extract valid signature\n");
			return 1; /* FAILED */
		}
	} else if (ctx->options->cmd == CMD_SIGN) {
		/* Create a new signature */
		sig = pe_create_signature(ctx);
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
static int pe_append_signature(FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	PKCS7 *outsig;
	u_char buf[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

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

	PUT_UINT32_LE(ctx->sign->len + 8 + ctx->sign->padlen, buf);
	PUT_UINT16_LE(WIN_CERT_REVISION_2_0, buf + 4);
	PUT_UINT16_LE(WIN_CERT_TYPE_PKCS_SIGNED_DATA, buf + 6);
	BIO_write(ctx->sign->outdata, buf, 8);
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
 * Update signature position and size, write back new checksum
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void pe_update_data_size(FILE_FORMAT_CTX *ctx)
{
	uint32_t checksum;
	u_char buf[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	
	if (ctx->options->cmd == CMD_VERIFY || ctx->options->cmd == CMD_EXTRACT) {
		return;
	}
	if (ctx->options->cmd != CMD_REMOVE) {
		/* Update signature position and size */
		(void)BIO_seek(ctx->sign->outdata, ctx->pe->header_size + 152 + ctx->pe->pe32plus * 16);
		/* Previous file end = signature table start */
		PUT_UINT32_LE(ctx->pe->fileend, buf);
		BIO_write(ctx->sign->outdata, buf, 4);
		PUT_UINT32_LE(ctx->sign->len + 8 + ctx->sign->padlen, buf);
		BIO_write(ctx->sign->outdata, buf, 4);
	}
	checksum = pe_calc_checksum(ctx->sign->outdata, ctx->pe);	
	/* write back checksum */
	(void)BIO_seek(ctx->sign->outdata, ctx->pe->header_size + 88);
	PUT_UINT32_LE(checksum, buf);
	BIO_write(ctx->sign->outdata, buf, 4);
}

/*
 * Free up an entire hash BIO chain
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void pe_ctx_free(FILE_FORMAT_CTX *ctx)
{
	BIO_free_all(ctx->sign->hash);
	ctx->sign->hash = ctx->sign->outdata = NULL;
}

/*
 * Deallocate a FILE_FORMAT_CTX structure, unmap indata file, unlink outfile
 * [in, out] ctx: structure holds all input and output data
 * [returns] none
 */
static void pe_ctx_cleanup(FILE_FORMAT_CTX *ctx)
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
	unmap_file(ctx->options->indata, ctx->pe->fileend);
	PKCS7_free(ctx->sign->sig);
	if (ctx->options->cmd != CMD_ADD)
		PKCS7_free(ctx->sign->cursig);
	OPENSSL_free(ctx->sign);
	OPENSSL_free(ctx->pe);
	OPENSSL_free(ctx);
}

/*
 * PE helper functions
 */
/* Compute a message digest value of a signed PE file. */
static int pe_calc_digest(char *indata, int mdtype, u_char *mdbuf, PE_HEADER *header)
{
	size_t written;
	uint32_t idx = 0, fileend;
	const EVP_MD *md = EVP_get_digestbynid(mdtype);
	BIO *bhash = BIO_new(BIO_f_md());

	if (!BIO_set_md(bhash, md)) {
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return 0;  /* FAILED */
	}
	BIO_push(bhash, BIO_new(BIO_s_null()));
	if (header->sigpos)
		fileend = header->sigpos;
	else
		fileend = header->fileend;

	/* header->header_size + 88 + 4 + 60 + header->pe32plus * 16 + 8 */
	if (!BIO_write_ex(bhash, indata, header->header_size + 88, &written)
		|| written != header->header_size + 88) {
		BIO_free_all(bhash);
		return 0; /* FAILED */
	}
	idx += (uint32_t)written + 4;
	if (!BIO_write_ex(bhash, indata + idx, 60 + header->pe32plus * 16, &written)
		|| written != 60 + header->pe32plus * 16) {
		BIO_free_all(bhash);
		return 0; /* FAILED */
	}
	idx += (uint32_t)written + 8;
	if (!bio_hash_data(bhash, indata, idx, fileend)) {
		printf("Unable to calculate digest\n");
		BIO_free_all(bhash);
		return 0;  /* FAILED */
	}
	if (!header->sigpos) {
		/* pad (with 0's) unsigned PE file to 8 byte boundary */
		int len = 8 - header->fileend % 8;
		if (len > 0 && len != 8) {
			char *buf = OPENSSL_malloc(8);
			memset(buf, 0, (size_t)len);
			BIO_write(bhash, buf, len);
			OPENSSL_free(buf);
		}
	}
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
	BIO_free_all(bhash);
	return 1;  /* OK */
}

static int pe_verify_header(char *indata, uint32_t filesize, PE_HEADER *header)
{
	if (filesize < 64) {
		printf("Corrupt DOS file - too short\n");
		return 0; /* FAILED */
	}
	/* SizeOfHeaders field specifies the combined size of an MS-DOS stub, PE header,
	 * and section headers rounded up to a multiple of FileAlignment.
	 * SizeOfHeaders must be < filesize and cannot be < 0x0000002C (44) in Windows 7
	 * because of a bug when checking section names for compatibility purposes */
	header->header_size = GET_UINT32_LE(indata + 60);
	if (header->header_size < 44 || header->header_size > filesize) {
		printf("Unexpected SizeOfHeaders field: 0x%08X\n", header->header_size);
		return 0; /* FAILED */
	}
	if (filesize < header->header_size + 176) {
		printf("Corrupt PE file - too short\n");
		return 0; /* FAILED */
	}
	if (memcmp(indata + header->header_size, "PE\0\0", 4)) {
		printf("Unrecognized DOS file type\n");
		return 0; /* FAILED */
	}
	/* Magic field identifies the state of the image file. The most common number is
	 * 0x10B, which identifies it as a normal executable file,
	 * 0x20B identifies it as a PE32+ executable,
	 * 0x107 identifies it as a ROM image (not supported) */
	header->magic = GET_UINT16_LE(indata + header->header_size + 24);
	if (header->magic == 0x20b) {
		header->pe32plus = 1;
	} else if (header->magic == 0x10b) {
		header->pe32plus = 0;
	} else {
		printf("Corrupt PE file - found unknown magic %04X\n", header->magic);
		return 0; /* FAILED */
	}
	/* The image file checksum */
	header->pe_checksum = GET_UINT32_LE(indata + header->header_size + 88);
	/* NumberOfRvaAndSizes field specifies the number of data-directory entries
	 * in the remainder of the optional header. Each describes a location and size. */
	header->nrvas = GET_UINT32_LE(indata + header->header_size + 116 + header->pe32plus * 16);
	if (header->nrvas < 5) {
		printf("Can not handle PE files without certificate table resource\n");
		return 0; /* FAILED */
	}
	/* Certificate Table field specifies the attribute certificate table address (4 bytes) and size (4 bytes) */
	header->sigpos = GET_UINT32_LE(indata + header->header_size + 152 + header->pe32plus * 16);
	header->siglen = GET_UINT32_LE(indata + header->header_size + 152 + header->pe32plus * 16 + 4);

	/* Since fix for MS Bulletin MS12-024 we can really assume
	   that signature should be last part of file */
	if ((header->sigpos > 0 && header->sigpos < filesize && header->sigpos + header->siglen != filesize)
		|| (header->sigpos >= filesize)) {
		printf("Corrupt PE file - current signature not at the end of the file\n");
		return 0; /* FAILED */
	}
	if ((header->sigpos > 0 && header->siglen == 0) || (header->sigpos == 0 && header->siglen > 0)) {
		printf("Corrupt signature\n");
		return 0; /* FAILED */
	}
	header->fileend = filesize;
	return 1; /* OK */
}

static PKCS7 *pe_get_sigfile(FILE_FORMAT_CTX *ctx)
{
	PKCS7 *sig = NULL;
	uint32_t sigfilesize;
	char *insigdata;
	PE_HEADER header;
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
		memset(&header, 0, sizeof(PE_HEADER));
		header.fileend = sigfilesize;
		header.siglen = sigfilesize;
		header.sigpos = 0;
		sig = pe_extract_existing_pkcs7(insigdata, &header);
	}
	unmap_file(insigdata, sigfilesize);
	return sig; /* OK */
}

static PKCS7 *pe_create_signature(FILE_FORMAT_CTX *ctx)
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

/*
 * A signed PE file is padded (with 0's) to 8 byte boundary.
 * Ignore any last odd byte in an unsigned file.
 */
static uint32_t pe_calc_checksum(BIO *bio, PE_HEADER *header)
{
	uint32_t checkSum = 0, offset = 0;
	int nread;
	unsigned short *buf = OPENSSL_malloc(SIZE_64K);

	/* recalculate the checksum */
	(void)BIO_seek(bio, 0);
	while ((nread = BIO_read(bio, buf, SIZE_64K)) > 0) {
		unsigned short val;
		int i;
		for (i = 0; i < nread / 2; i++) {
			val = LE_UINT16(buf[i]);
			if (offset == header->header_size + 88 || offset == header->header_size + 90)
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

/* Compute a checkSum value of the signed or unsigned PE file. */
static uint32_t pe_calc_realchecksum(FILE_FORMAT_CTX *ctx)
{
	uint32_t n = 0, checkSum = 0, offset = 0;
	BIO *bio = BIO_new(BIO_s_mem());
	unsigned short *buf = OPENSSL_malloc(SIZE_64K);

	/* calculate the checkSum */
	while (n < ctx->pe->fileend) {
		size_t i, written, nread;
		size_t left = ctx->pe->fileend - n;
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
			if (offset == ctx->pe->header_size + 88
				|| offset == ctx->pe->header_size + 90) {
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

static int pe_modify_header(FILE_FORMAT_CTX *ctx)
{
	size_t i, len, written;
	char *buf;

	i = len = ctx->pe->header_size + 88;
	if (!BIO_write_ex(ctx->sign->hash, ctx->options->indata, len, &written)
		|| written != len)
		return 0; /* FAILED */
	buf = OPENSSL_malloc(SIZE_64K);
	memset(buf, 0, 4);
	BIO_write(ctx->sign->outdata, buf, 4); /* zero out checksum */
	i += 4;
	len = 60 + ctx->pe->pe32plus * 16;
	if (!BIO_write_ex(ctx->sign->hash, ctx->options->indata + i, len, &written)
		|| written != len) {
		OPENSSL_free(buf);
		return 0; /* FAILED */
	}
	i += 60 + ctx->pe->pe32plus * 16;
	memset(buf, 0, 8);
	BIO_write(ctx->sign->outdata, buf, 8); /* zero out sigtable offset + pos */
	i += 8;
	len = ctx->pe->fileend - i;
	while (len > 0) {
		if (!BIO_write_ex(ctx->sign->hash, ctx->options->indata + i, len, &written)) {
			OPENSSL_free(buf);
			return 0; /* FAILED */
		}
		len -= written;
		i += written;
	}
	/* pad (with 0's) pe file to 8 byte boundary */
	len = 8 - ctx->pe->fileend % 8;
	if (len != 8) {
		memset(buf, 0, len);
		if (!BIO_write_ex(ctx->sign->hash, buf, len, &written) || written != len) {
			OPENSSL_free(buf);
			return 0; /* FAILED */
		}
		ctx->pe->fileend += (uint32_t)len;
	}
	OPENSSL_free(buf);
	return 1; /* OK */
}

/*
 * Page hash support
 */
static int pe_extract_page_hash(SpcAttributeTypeAndOptionalValue *obj,
	u_char **ph, int *phlen, int *phtype)
{
	const u_char *blob;
	SpcPeImageData *id;
	SpcSerializedObject *so;
	int l, l2;
	char buf[128];

	*phlen = 0;
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
		return 1; /* OK - this is not SpcSerializedObject structure that contains page hashes */
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


static u_char *pe_calc_page_hash(FILE_FORMAT_CTX *ctx, int phtype, int *rphlen)
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
	nsections = GET_UINT16_LE(ctx->options->indata + ctx->pe->header_size + 6);
	if (nsections == 0 || nsections > UINT16_MAX) {
		printf("Corrupted number of sections: 0x%08X\n", nsections);
		return NULL; /* FAILED */
	}
	/* FileAlignment is the alignment factor (in bytes) that is used to align
	 * the raw data of sections in the image file. The value should be a power
	 * of 2 between 512 and 64 K, inclusive. The default is 512. */
	alignment = GET_UINT32_LE(ctx->options->indata + ctx->pe->header_size + 60);
	if (alignment < 512 || alignment > UINT16_MAX) {
		printf("Corrupted file alignment factor: 0x%08X\n", alignment);
		return NULL; /* FAILED */
	}
	/* SectionAlignment is the alignment (in bytes) of sections when they are
	 * loaded into memory. It must be greater than or equal to FileAlignment.
	 * The default is the page size for the architecture.
	 * The large page size is at most 4 MB.
	 * https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200 */
	pagesize = GET_UINT32_LE(ctx->options->indata + ctx->pe->header_size + 56);
	if (pagesize == 0 || pagesize < alignment || pagesize > 4194304) {
		printf("Corrupted page size: 0x%08X\n", pagesize);
		return NULL; /* FAILED */
	}
	/* SizeOfHeaders is the combined size of an MS-DOS stub, PE header,
	 * and section headers rounded up to a multiple of FileAlignment. */
	hdrsize = GET_UINT32_LE(ctx->options->indata + ctx->pe->header_size + 84);
	if (hdrsize < ctx->pe->header_size || hdrsize > UINT32_MAX) {
		printf("Corrupted headers size: 0x%08X\n", hdrsize);
		return NULL; /* FAILED */
	}
	/* SizeOfOptionalHeader is the size of the optional header, which is
	 * required for executable files, but for object files should be zero,
	 * and can't be bigger than the file */
	opthdr_size = GET_UINT16_LE(ctx->options->indata + ctx->pe->header_size + 20);
	if (opthdr_size == 0 || opthdr_size > ctx->pe->fileend) {
		printf("Corrupted optional header size: 0x%08X\n", opthdr_size);
		return NULL; /* FAILED */
	}
	pphlen = 4 + EVP_MD_size(md);
	phlen = pphlen * (3 + (int)nsections + (int)(ctx->pe->fileend / pagesize));

	bhash = BIO_new(BIO_f_md());
	if (!BIO_set_md(bhash, md)) {
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	BIO_push(bhash, BIO_new(BIO_s_null()));
	if (!BIO_write_ex(bhash, ctx->options->indata, ctx->pe->header_size + 88, &written)
		|| written != ctx->pe->header_size + 88) {
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	if (!BIO_write_ex(bhash, ctx->options->indata + ctx->pe->header_size + 92, 60 + ctx->pe->pe32plus*16, &written)
		|| written != 60 + ctx->pe->pe32plus*16) {
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	if (!BIO_write_ex(bhash, ctx->options->indata + ctx->pe->header_size + 160 + ctx->pe->pe32plus*16,
		hdrsize - (ctx->pe->header_size + 160 + ctx->pe->pe32plus*16), &written)
		|| written != hdrsize - (ctx->pe->header_size + 160 + ctx->pe->pe32plus*16)) {
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

	sections = ctx->options->indata + ctx->pe->header_size + 24 + opthdr_size;
	for (i=0; i<nsections; i++) {
		/* Resource Table address and size */
		rs = GET_UINT32_LE(sections + 16);
		ro = GET_UINT32_LE(sections + 20);
		if (rs == 0 || rs >= UINT32_MAX) {
			continue;
		}
		for (l=0; l < rs; l+=pagesize, pi++) {
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

static int pe_compare_page_hash(FILE_FORMAT_CTX *ctx, u_char *ph, int phlen, int phtype)
{
	int mdok, cphlen = 0;
	u_char *cph;

	printf("Page hash algorithm  : %s\n", OBJ_nid2sn(phtype));
	print_hash("Page hash            ", "...", ph, (phlen < 32) ? phlen : 32);
	cph = pe_calc_page_hash(ctx, phtype, &cphlen);
	mdok = (phlen == cphlen) && !memcmp(ph, cph, (size_t)phlen);
	print_hash("Calculated page hash ", mdok ? "...\n" : "... MISMATCH!!!\n", cph, (cphlen < 32) ? cphlen : 32);
	OPENSSL_free(cph);
	return mdok;
}

static SpcLink *get_page_hash_link(FILE_FORMAT_CTX *ctx, int phtype)
{
	u_char *ph, *p, *tmp;
	int l, phlen;
	ASN1_TYPE *tostr;
	SpcAttributeTypeAndOptionalValue *aval;
	ASN1_TYPE *taval;
	SpcSerializedObject *so;
	SpcLink *link;
	STACK_OF(ASN1_TYPE) *oset, *aset;

	ph = pe_calc_page_hash(ctx, phtype, &phlen);
	if (!ph) {
		printf("Failed to calculate page hash\n");
		return NULL; /* FAILED */
	}
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
 * Retrieve and verify a decoded PKCS7 struct corresponding
 * to the existing signature of the PE file.
 */
static PKCS7 *pe_extract_existing_pkcs7(char *indata, PE_HEADER *header)
{
	uint32_t pos = 0;
	PKCS7 *p7 = NULL;

	if (header->siglen == 0 || header->siglen > header->fileend) {
		printf("Corrupted signature length: 0x%08X\n", header->siglen);
		return NULL; /* FAILED */
	}
	while (pos < header->siglen) {
		uint32_t l = GET_UINT32_LE(indata + header->sigpos + pos);
		uint16_t certrev  = GET_UINT16_LE(indata + header->sigpos + pos + 4);
		uint16_t certtype = GET_UINT16_LE(indata + header->sigpos + pos + 6);
		if (certrev == WIN_CERT_REVISION_2_0 && certtype == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
			const u_char *blob = (u_char *)indata + header->sigpos + pos + 8;
			p7 = d2i_PKCS7(NULL, &blob, l - 8);
		}
		if (l%8)
			l += (8 - l%8);
		pos += l;
	}
	return p7;
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
