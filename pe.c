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
static TYPE_DATA *pe_init(GLOBAL_OPTIONS *options);
static ASN1_OBJECT *pe_spc_image_data(TYPE_DATA *tdata, u_char **p, int *plen);
static int pe_verify_signed(TYPE_DATA *tdata);
static int pe_extract_signature(TYPE_DATA *tdata);
static int pe_remove_signature(TYPE_DATA *tdata);
static int pe_prepare_signature(TYPE_DATA *tdata);
static int pe_append_signature(TYPE_DATA *tdata);
static void pe_update_data_size(TYPE_DATA *tdata);
static void pe_free_data(TYPE_DATA *tdata);
static void pe_cleanup_data(TYPE_DATA *tdata);

FILE_FORMAT file_format_pe = {
	.init = pe_init,
	.get_data_blob = pe_spc_image_data,
	.verify_signed = pe_verify_signed,
	.extract_signature = pe_extract_signature,
	.remove_signature = pe_remove_signature,
	.prepare_signature = pe_prepare_signature,
	.append_signature = pe_append_signature,
	.update_data_size = pe_update_data_size,
	.free_data = pe_free_data,
	.cleanup_data = pe_cleanup_data
};

/* Common function */
int pe_calc_digest(char *indata, int mdtype, u_char *mdbuf, PE_HEADER *header);

/* Prototypes */
static int pe_verify_header(char *indata, uint32_t filesize, PE_HEADER *header);
static PKCS7 *get_pkcs7(TYPE_DATA *tdata);
static uint32_t pe_calc_checksum(BIO *bio, PE_HEADER *header);
static void pe_recalc_checksum(BIO *bio, PE_HEADER *header);
static uint32_t pe_calc_realchecksum(TYPE_DATA *tdata);
static int pe_modify_header(TYPE_DATA *tdata);
static PKCS7 *pe_extract_existing_pkcs7(char *indata, PE_HEADER *header);
static int pe_verify_pkcs7(TYPE_DATA *tdata, SIGNATURE *signature);
static SpcLink *get_page_hash_link(int phtype, char *indata, PE_HEADER *header);


/*
 * FILE_FORMAT method definitions
 */
static TYPE_DATA *pe_init(GLOBAL_OPTIONS *options)
{
	TYPE_DATA *tdata;
	PE_HEADER *header;
	SIGN_DATA *sign;
	BIO *hash, *outdata = NULL;
	uint32_t filesize;
	
	if (options->jp >= 0)
		printf("Warning: -jp option is only valid for CAB files\n");
	if (options->add_msi_dse == 1)
		printf("Warning: -add-msi-dse option is only valid for MSI files\n");

	filesize = input_validation(options, FILE_TYPE_PE);
	if (filesize == 0)
		return NULL; /* FAILED */

	header = OPENSSL_zalloc(sizeof(PE_HEADER));
	if (!pe_verify_header(options->indata, filesize, header)) {
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	hash = BIO_new(BIO_f_md());
	if (!BIO_set_md(hash, options->md)) {
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(hash);
		OPENSSL_free(header);
		return NULL; /* FAILED */
	}
	if (options->cmd != CMD_VERIFY) {
		/* Create outdata file */
		outdata = BIO_new_file(options->outfile, FILE_CREATE_MODE);
		if (outdata == NULL) {
			printf("Failed to create file: %s\n", options->outfile);
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

	tdata = OPENSSL_malloc(sizeof(TYPE_DATA));
	tdata->format = &file_format_pe;
	tdata->options = options;
	tdata->sign = sign;
	tdata->pe = header;
	return tdata;
}

static ASN1_OBJECT *pe_spc_image_data(TYPE_DATA *tdata, u_char **p, int *plen)
{
	int phtype;
	ASN1_OBJECT *dtype;
	SpcPeImageData *pid = SpcPeImageData_new();

	ASN1_BIT_STRING_set_bit(pid->flags, 0, 1);
	if (tdata->options->pagehash) {
		SpcLink *link;
		phtype = NID_sha1;
		if (EVP_MD_size(tdata->options->md) > EVP_MD_size(EVP_sha1()))
			phtype = NID_sha256;
		link = get_page_hash_link(phtype, tdata->options->indata, tdata->pe);
		if (!link)
			return NULL; /* FAILED */
		pid->file = link;
	} else {
		pid->file = get_obsolete_link();
	}
	*plen = i2d_SpcPeImageData(pid, NULL);
	*p = OPENSSL_malloc((size_t)*plen);
	i2d_SpcPeImageData(pid, p);
	*p -= *plen;
	dtype = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1);
	SpcPeImageData_free(pid);
	return dtype; /* OK */
}

static void pe_update_data_size(TYPE_DATA *tdata)
{
	u_char buf[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (tdata->options->cmd == CMD_SIGN || tdata->options->cmd == CMD_ADD
		|| tdata->options->cmd == CMD_ATTACH) {
		/* Update signature position and size */
		(void)BIO_seek(tdata->sign->outdata, tdata->pe->header_size + 152 + tdata->pe->pe32plus * 16);
		/* Previous file end = signature table start */
		PUT_UINT32_LE(tdata->pe->fileend, buf);
		BIO_write(tdata->sign->outdata, buf, 4);
		PUT_UINT32_LE(tdata->sign->len + 8 + tdata->sign->padlen, buf);
		BIO_write(tdata->sign->outdata, buf, 4);
	}
	if (tdata->options->cmd == CMD_SIGN || tdata->options->cmd == CMD_REMOVE
		|| tdata->options->cmd == CMD_ADD || tdata->options->cmd == CMD_ATTACH)
		pe_recalc_checksum(tdata->sign->outdata, tdata->pe);
}

static int pe_verify_signed(TYPE_DATA *tdata)
{
	int i, peok = 1, ret = 1;
	uint32_t real_pe_checksum;
	PKCS7 *p7;
	STACK_OF(SIGNATURE) *signatures = sk_SIGNATURE_new_null();

	if (!tdata) {
		printf("Init error\n\n");
		goto out;
	}
	if (tdata->pe->siglen == 0)
		tdata->pe->sigpos = tdata->pe->fileend;

	/* check PE checksum */
	printf("Current PE checksum   : %08X\n", tdata->pe->pe_checksum);
	real_pe_checksum = pe_calc_realchecksum(tdata);
	if (tdata->pe->pe_checksum && tdata->pe->pe_checksum != real_pe_checksum)
		peok = 0;
	printf("Calculated PE checksum: %08X%s\n\n", real_pe_checksum, peok ? "" : "    MISMATCH!!!");

	if (tdata->pe->sigpos == 0 || tdata->pe->siglen == 0
		|| tdata->pe->sigpos > tdata->pe->fileend) {
		printf("No signature found\n\n");
		goto out;
	}
	if (tdata->pe->siglen != GET_UINT32_LE(tdata->options->indata + tdata->pe->sigpos)) {
		printf("Invalid signature\n\n");
		goto out;
	}
	p7 = pe_extract_existing_pkcs7(tdata->options->indata, tdata->pe);
	if (!p7) {
		printf("Failed to extract PKCS7 data\n\n");
		goto out;
	}
	if (!append_signature_list(&signatures, p7, 1)) {
		printf("Failed to create signature list\n\n");
		PKCS7_free(p7);
		goto out;
	}
	for (i = 0; i < sk_SIGNATURE_num(signatures); i++) {
		SIGNATURE *signature = sk_SIGNATURE_value(signatures, i);
		printf("Signature Index: %d %s\n", i, i==0 ? " (Primary Signature)" : "");
		ret &= pe_verify_pkcs7(tdata, signature);
	}
	printf("Number of verified signatures: %d\n", i);
out:
	sk_SIGNATURE_pop_free(signatures, signature_free);
	return ret;
}

static int pe_extract_signature(TYPE_DATA *tdata)
{
	int ret = 0;
	PKCS7 *sig;
	size_t written;

	if (tdata->pe->sigpos == 0) {
		printf("PE file does not have any signature\n");
		return 1; /* FAILED */
	}
	(void)BIO_reset(tdata->sign->outdata);
	if (tdata->options->output_pkcs7) {
		sig = pe_extract_existing_pkcs7(tdata->options->indata, tdata->pe);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(tdata->sign->outdata, sig);
		PKCS7_free(sig);
	} else
		if (!BIO_write_ex(tdata->sign->outdata,
			tdata->options->indata + tdata->pe->sigpos,
			tdata->pe->siglen, &written) || written != tdata->pe->siglen)
			ret = 1; /* FAILED */
	return ret;
}

static int pe_remove_signature(TYPE_DATA *tdata)
{
	if (tdata->pe->sigpos == 0) {
		printf("PE file does not have any signature\n");
		return 1; /* FAILED */
	}
	return pe_prepare_signature(tdata);
}

static int pe_prepare_signature(TYPE_DATA *tdata)
{
	PKCS7 *sig = NULL;

	/* Obtain a current signature from previously-signed file */
	if ((tdata->options->cmd == CMD_SIGN && tdata->options->nest)
		|| (tdata->options->cmd == CMD_ATTACH && tdata->options->nest)
		|| tdata->options->cmd == CMD_ADD) {
		tdata->sign->cursig = pe_extract_existing_pkcs7(tdata->options->indata, tdata->pe);
		if (!tdata->sign->cursig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		if (tdata->options->cmd == CMD_ADD)
			sig = tdata->sign->cursig;
	}
	if (tdata->pe->sigpos > 0) {
		/* Strip current signature */
		tdata->pe->fileend = tdata->pe->sigpos;
	}
	if (!pe_modify_header(tdata)) {
		printf("Unable to modify file header\n");
		return 1; /* FAILED */
	}
	/* Obtain an existing signature or create a new one */
	if ((tdata->options->cmd == CMD_ATTACH) || (tdata->options->cmd == CMD_SIGN))
		sig = get_pkcs7(tdata);

	tdata->sign->sig = sig;
	return 0; /* OK */
}

static int pe_append_signature(TYPE_DATA *tdata)
{
	u_char *p = NULL;
	PKCS7 *outsig;
	u_char buf[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (tdata->options->nest) {
		if (tdata->sign->cursig == NULL) {
			printf("Internal error: No 'cursig' was extracted\n");
			return 1; /* FAILED */
		}
		if (pkcs7_set_nested_signature(tdata) == 0) {
			printf("Unable to append the nested signature to the current signature\n");
			return 1; /* FAILED */
		}
		outsig = tdata->sign->cursig;
	} else {
		outsig = tdata->sign->sig;
	}
	/* Append signature to the outfile */
	if (((tdata->sign->len = i2d_PKCS7(outsig, NULL)) <= 0)
		|| (p = OPENSSL_malloc((size_t)tdata->sign->len)) == NULL) {
		printf("i2d_PKCS memory allocation failed: %d\n", tdata->sign->len);
		return 1; /* FAILED */
	}
	i2d_PKCS7(outsig, &p);
	p -= tdata->sign->len;
	tdata->sign->padlen = (8 - tdata->sign->len % 8) % 8;

	PUT_UINT32_LE(tdata->sign->len + 8 + tdata->sign->padlen, buf);
	PUT_UINT16_LE(WIN_CERT_REVISION_2_0, buf + 4);
	PUT_UINT16_LE(WIN_CERT_TYPE_PKCS_SIGNED_DATA, buf + 6);
	BIO_write(tdata->sign->outdata, buf, 8);
	BIO_write(tdata->sign->outdata, p, tdata->sign->len);
	/* pad (with 0's) asn1 blob to 8 byte boundary */
	if (tdata->sign->padlen > 0) {
		memset(p, 0, (size_t)tdata->sign->padlen);
		BIO_write(tdata->sign->outdata, p, tdata->sign->padlen);
	}
	OPENSSL_free(p);
	return 0; /* OK */
}

static void pe_free_data(TYPE_DATA *tdata)
{
	BIO_free_all(tdata->sign->hash);
	tdata->sign->hash = tdata->sign->outdata = NULL;
}

static void pe_cleanup_data(TYPE_DATA *tdata)
{
	if (tdata->sign->hash) {
		BIO_free_all(tdata->sign->hash);
	}
	if (tdata->sign->outdata) {
		if (tdata->options->outfile) {
#ifdef WIN32
			_unlink(tdata->options->outfile);
#else
			unlink(tdata->options->outfile);
#endif /* WIN32 */
		}
	}
	unmap_file(tdata->options->indata, tdata->pe->fileend);
	PKCS7_free(tdata->sign->sig);
	if (tdata->options->cmd != CMD_ADD)
		PKCS7_free(tdata->sign->cursig);
	OPENSSL_free(tdata->sign);
	OPENSSL_free(tdata->pe);
	OPENSSL_free(tdata);
}

/*
 * PE helper functions
 */
/* Compute a message digest value of a signed PE file. */
int pe_calc_digest(char *indata, int mdtype, u_char *mdbuf, PE_HEADER *header)
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
	if (!bio_hash_data(indata, bhash, idx, 0, fileend)) {
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

static PKCS7 *pe_get_sigfile(TYPE_DATA *tdata)
{
	PKCS7 *sig = NULL;
	uint32_t sigfilesize;
	char *insigdata;
	PE_HEADER header;
	BIO *sigbio;
	const char pemhdr[] = "-----BEGIN PKCS7-----";

	sigfilesize = get_file_size(tdata->options->sigfile);
	if (!sigfilesize) {
		return NULL; /* FAILED */
	}
	insigdata = map_file(tdata->options->sigfile, sigfilesize);
	if (!insigdata) {
		printf("Failed to open file: %s\n", tdata->options->sigfile);
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

static PKCS7 *pe_create_signature(TYPE_DATA *tdata)
{
	int i, signer = -1;
	PKCS7 *sig;
	PKCS7_SIGNER_INFO *si = NULL;

	sig = PKCS7_new();
	PKCS7_set_type(sig, NID_pkcs7_signed);

	if (tdata->options->cert != NULL) {
		/*
		 * the private key and corresponding certificate are parsed from the PKCS12
		 * structure or loaded from the security token, so we may omit to check
		 * the consistency of a private key with the public key in an X509 certificate
		 */
		si = PKCS7_add_signature(sig, tdata->options->cert, tdata->options->pkey, tdata->options->md);
		if (si == NULL)
			return NULL; /* FAILED */
	} else {
		/* find the signer's certificate located somewhere in the whole certificate chain */
		for (i=0; i<sk_X509_num(tdata->options->certs); i++) {
			X509 *signcert = sk_X509_value(tdata->options->certs, i);
			if (X509_check_private_key(signcert, tdata->options->pkey)) {
				si = PKCS7_add_signature(sig, signcert, tdata->options->pkey, tdata->options->md);
				signer = i;
				break;
			}
		}
		if (si == NULL) {
		    printf("Failed to checking the consistency of a private key: %s\n",
				tdata->options->keyfile);
		    printf("          with a public key in any X509 certificate: %s\n\n",
				tdata->options->certfile);
		    return NULL; /* FAILED */
		}
	}
	pkcs7_add_signing_time(si, tdata->options->time);
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
		V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1));

	if (!add_purpose_attribute(si, tdata->options->comm))
		return NULL; /* FAILED */

	if ((tdata->options->desc || tdata->options->url) &&
			!add_opus_attribute(si, tdata->options->desc, tdata->options->url)) {
		printf("Couldn't allocate memory for opus info\n");
		return NULL; /* FAILED */
	}
	PKCS7_content_new(sig, NID_pkcs7_data);

	/* add the signer's certificate */
	if (tdata->options->cert != NULL)
		PKCS7_add_certificate(sig, tdata->options->cert);
	if (signer != -1)
		PKCS7_add_certificate(sig, sk_X509_value(tdata->options->certs, signer));

	/* add the certificate chain */
	for (i=0; i<sk_X509_num(tdata->options->certs); i++) {
		if (i == signer)
			continue;
		PKCS7_add_certificate(sig, sk_X509_value(tdata->options->certs, i));
	}
	/* add all cross certificates */
	if (tdata->options->xcerts) {
		for (i=0; i<sk_X509_num(tdata->options->xcerts); i++)
			PKCS7_add_certificate(sig, sk_X509_value(tdata->options->xcerts, i));
	}
	/* add crls */
	if (tdata->options->crls) {
		for (i=0; i<sk_X509_CRL_num(tdata->options->crls); i++)
			PKCS7_add_crl(sig, sk_X509_CRL_value(tdata->options->crls, i));
	}
	if (!set_indirect_data_blob(tdata, sig)) {
		PKCS7_free(sig);
		printf("Signing failed\n");
		return NULL; /* FAILED */
	}
	return sig; /* OK */
}
/* Obtain an existing signature or create a new one */
static PKCS7 *get_pkcs7(TYPE_DATA *tdata)
{
	PKCS7 *sig = NULL;

	if (tdata->options->cmd == CMD_ATTACH) {
		sig = pe_get_sigfile(tdata);
		if (!sig) {
			printf("Unable to extract valid signature\n");
			return NULL; /* FAILED */
		}
	} else if (tdata->options->cmd == CMD_SIGN) {
		sig = pe_create_signature(tdata);
		if (!sig) {
			printf("Creating a new signature failed\n");
			return NULL; /* FAILED */
		}
	}
	return sig;
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

static void pe_recalc_checksum(BIO *bio, PE_HEADER *header)
{
	uint32_t checksum = pe_calc_checksum(bio, header);
	char buf[4];

	/* write back checksum */
	(void)BIO_seek(bio, header->header_size + 88);
	PUT_UINT32_LE(checksum, buf);
	BIO_write(bio, buf, 4);
}


/* Compute a checkSum value of the signed or unsigned PE file. */
static uint32_t pe_calc_realchecksum(TYPE_DATA *tdata)
{
	uint32_t n = 0, checkSum = 0, offset = 0;
	BIO *bio = BIO_new(BIO_s_mem());
	unsigned short *buf = OPENSSL_malloc(SIZE_64K);

	/* calculate the checkSum */
	while (n < tdata->pe->fileend) {
		size_t i, written, nread;
		size_t left = tdata->pe->fileend - n;
		unsigned short val;
		if (left > SIZE_64K)
			left = SIZE_64K;
		if (!BIO_write_ex(bio, tdata->options->indata + n, left, &written))
			goto err; /* FAILED */
		(void)BIO_seek(bio, 0);
		n += (uint32_t)written;
		if (!BIO_read_ex(bio, buf, written, &nread))
			goto err; /* FAILED */
		for (i = 0; i < nread / 2; i++) {
			val = LE_UINT16(buf[i]);
			if (offset == tdata->pe->header_size + 88
				|| offset == tdata->pe->header_size + 90) {
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

static int pe_modify_header(TYPE_DATA *tdata)
{
	size_t i, len, written;
	char *buf;

	i = len = tdata->pe->header_size + 88;
	if (!BIO_write_ex(tdata->sign->hash, tdata->options->indata, len, &written)
		|| written != len)
		return 0; /* FAILED */
	buf = OPENSSL_malloc(SIZE_64K);
	memset(buf, 0, 4);
	BIO_write(tdata->sign->outdata, buf, 4); /* zero out checksum */
	i += 4;
	len = 60 + tdata->pe->pe32plus * 16;
	if (!BIO_write_ex(tdata->sign->hash, tdata->options->indata + i, len, &written)
		|| written != len) {
		OPENSSL_free(buf);
		return 0; /* FAILED */
	}
	i += 60 + tdata->pe->pe32plus * 16;
	memset(buf, 0, 8);
	BIO_write(tdata->sign->outdata, buf, 8); /* zero out sigtable offset + pos */
	i += 8;
	len = tdata->pe->fileend - i;
	while (len > 0) {
		if (!BIO_write_ex(tdata->sign->hash, tdata->options->indata + i, len, &written)) {
			OPENSSL_free(buf);
			return 0; /* FAILED */
		}
		len -= written;
		i += written;
	}
	/* pad (with 0's) pe file to 8 byte boundary */
	len = 8 - tdata->pe->fileend % 8;
	if (len != 8) {
		memset(buf, 0, len);
		if (!BIO_write_ex(tdata->sign->hash, buf, len, &written) || written != len) {
			OPENSSL_free(buf);
			return 0; /* FAILED */
		}
		tdata->pe->fileend += (uint32_t)len;
	}
	OPENSSL_free(buf);
	return 1; /* OK */
}

/* Page hash support. */
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

static u_char *pe_calc_page_hash(char *indata, uint32_t header_size,
	uint32_t pe32plus, uint32_t sigpos, int phtype, int *rphlen)
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
	nsections = GET_UINT16_LE(indata + header_size + 6);
	if (nsections == 0 || nsections > UINT16_MAX) {
		printf("Corrupted number of sections: 0x%08X\n", nsections);
		return NULL; /* FAILED */
	}
	/* FileAlignment is the alignment factor (in bytes) that is used to align
	 * the raw data of sections in the image file. The value should be a power
	 * of 2 between 512 and 64 K, inclusive. The default is 512. */
	alignment = GET_UINT32_LE(indata + header_size + 60);
	if (alignment < 512 || alignment > UINT16_MAX) {
		printf("Corrupted file alignment factor: 0x%08X\n", alignment);
		return NULL; /* FAILED */
	}
	/* SectionAlignment is the alignment (in bytes) of sections when they are
	 * loaded into memory. It must be greater than or equal to FileAlignment.
	 * The default is the page size for the architecture.
	 * The large page size is at most 4 MB.
	 * https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200 */
	pagesize = GET_UINT32_LE(indata + header_size + 56);
	if (pagesize == 0 || pagesize < alignment || pagesize > 4194304) {
		printf("Corrupted page size: 0x%08X\n", pagesize);
		return NULL; /* FAILED */
	}
	/* SizeOfHeaders is the combined size of an MS-DOS stub, PE header,
	 * and section headers rounded up to a multiple of FileAlignment. */
	hdrsize = GET_UINT32_LE(indata + header_size + 84);
	if (hdrsize < header_size || hdrsize > UINT32_MAX) {
		printf("Corrupted headers size: 0x%08X\n", hdrsize);
		return NULL; /* FAILED */
	}
	/* SizeOfOptionalHeader is the size of the optional header, which is
	 * required for executable files, but for object files should be zero,
	 * and can't be bigger than the file */
	opthdr_size = GET_UINT16_LE(indata + header_size + 20);
	if (opthdr_size == 0 || opthdr_size > sigpos) {
		printf("Corrupted optional header size: 0x%08X\n", opthdr_size);
		return NULL; /* FAILED */
	}
	pphlen = 4 + EVP_MD_size(md);
	phlen = pphlen * (3 + (int)nsections + (int)(sigpos / pagesize));

	bhash = BIO_new(BIO_f_md());
	if (!BIO_set_md(bhash, md)) {
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	BIO_push(bhash, BIO_new(BIO_s_null()));
	if (!BIO_write_ex(bhash, indata, header_size + 88, &written)
		|| written != header_size + 88) {
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	if (!BIO_write_ex(bhash, indata + header_size + 92, 60 + pe32plus*16, &written)
		|| written != 60 + pe32plus*16) {
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	if (!BIO_write_ex(bhash, indata + header_size + 160 + pe32plus*16,
		hdrsize - (header_size + 160 + pe32plus*16), &written)
		|| written != hdrsize - (header_size + 160 + pe32plus*16)) {
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

	sections = indata + header_size + 24 + opthdr_size;
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
				if (!BIO_write_ex(bhash, indata + ro + l, rs - l, &written)
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
				if (!BIO_write_ex(bhash, indata + ro + l, pagesize, &written)
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

static int pe_print_page_hash(char *indata, PE_HEADER *header, u_char *ph, int phlen, int phtype)
{
	int mdok, cphlen = 0;
	u_char *cph;

	printf("Page hash algorithm  : %s\n", OBJ_nid2sn(phtype));
	print_hash("Page hash            ", "...", ph, (phlen < 32) ? phlen : 32);
	cph = pe_calc_page_hash(indata, header->header_size, header->pe32plus, header->sigpos, phtype, &cphlen);
	mdok = (phlen == cphlen) && !memcmp(ph, cph, (size_t)phlen);
	print_hash("Calculated page hash ", mdok ? "...\n" : "... MISMATCH!!!\n", cph, (cphlen < 32) ? cphlen : 32);
	OPENSSL_free(cph);
	return mdok;
}

static SpcLink *get_page_hash_link(int phtype, char *indata, PE_HEADER *header)
{
	u_char *ph, *p, *tmp;
	int l, phlen;
	ASN1_TYPE *tostr;
	SpcAttributeTypeAndOptionalValue *aval;
	ASN1_TYPE *taval;
	SpcSerializedObject *so;
	SpcLink *link;
	STACK_OF(ASN1_TYPE) *oset, *aset;

	ph = pe_calc_page_hash(indata, header->header_size, header->pe32plus,
			header->fileend, phtype, &phlen);
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

static int pe_verify_pkcs7(TYPE_DATA *tdata, SIGNATURE *signature)
{
	int ret = 1, mdtype = -1, phtype = -1;
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
				goto out;
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
		goto out;
	}
	if (!pe_calc_digest(tdata->options->indata, mdtype, cmdbuf, tdata->pe)) {
		printf("Failed to calculate message digest\n\n");
		goto out;
	}
	if (!compare_digests(mdbuf, cmdbuf, mdtype)) {
		printf("Signature verification: failed\n\n");
		goto out;
	}
	if (phlen > 0 && !pe_print_page_hash(tdata->options->indata, tdata->pe, ph, phlen, phtype)) {
		printf("Signature verification: failed\n\n");
		goto out;
	}

	ret = verify_signature(tdata, signature);
out:
	if (ret)
		ERR_print_errors_fp(stdout);
	OPENSSL_free(ph);
	return ret;
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
