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
static TYPE_DATA *cab_init(GLOBAL_OPTIONS *options);
static ASN1_OBJECT *cab_obsolete_link(TYPE_DATA *tdata, u_char **p, int *plen);
static int cab_verify_signed(TYPE_DATA *tdata);
static int cab_extract_signature(TYPE_DATA *tdata);
static int cab_remove_signature(TYPE_DATA *tdata);
static int cab_prepare_signature(TYPE_DATA *tdata);
static int cab_append_signature(TYPE_DATA *tdata);
static void cab_update_data_size(TYPE_DATA *tdata);
static void cab_free_data(TYPE_DATA *tdata);
static void cab_cleanup_data(TYPE_DATA *tdata);

FILE_FORMAT file_format_cab = {
	.init = cab_init,
	.get_data_blob = cab_obsolete_link,
	.verify_signed = cab_verify_signed,
	.extract_signature = cab_extract_signature,
	.remove_signature = cab_remove_signature,
	.prepare_signature = cab_prepare_signature,
	.append_signature = cab_append_signature,
	.update_data_size = cab_update_data_size,
	.free_data = cab_free_data,
	.cleanup_data = cab_cleanup_data
};

/* Common function */
static int cab_calc_digest(char *indata, int mdtype, u_char *mdbuf, CAB_HEADER *header);

/* Prototypes */
static int cab_verify_header(char *indata, uint32_t filesize, CAB_HEADER *header);
static PKCS7 *get_pkcs7(TYPE_DATA *tdata);
static void cab_add_jp_attribute(PKCS7_SIGNER_INFO *si, int jp);
static PKCS7 *cab_extract_existing_pkcs7(char *indata, CAB_HEADER *header);
static int cab_verify_pkcs7(TYPE_DATA *tdata, SIGNATURE *signature);
static void cab_optional_names(uint16_t flags, char *indata, BIO *outdata, size_t *len);
static int cab_modify_header(TYPE_DATA *tdata);
static int cab_add_header(TYPE_DATA *tdata);


/*
 * FILE_FORMAT method definitions
 */
static TYPE_DATA *cab_init(GLOBAL_OPTIONS *options)
{
	TYPE_DATA *tdata;
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

	tdata = OPENSSL_malloc(sizeof(TYPE_DATA));
	tdata->format = &file_format_cab;
	tdata->options = options;
	tdata->sign = sign;
	tdata->cab = header;
	return tdata;
}

static ASN1_OBJECT *cab_obsolete_link(TYPE_DATA *tdata, u_char **p, int *plen)
{
	ASN1_OBJECT *dtype;
	SpcLink *link = get_obsolete_link();

	/* squash the unused parameter warning */
	(void)tdata;

	*plen = i2d_SpcLink(link, NULL);
	*p = OPENSSL_malloc((size_t)*plen);
	i2d_SpcLink(link, p);
	*p -= *plen;
	dtype = OBJ_txt2obj(SPC_CAB_DATA_OBJID, 1);
	SpcLink_free(link);
	return dtype; /* OK */
}

static void cab_update_data_size(TYPE_DATA *tdata)
{
	if (tdata->options->cmd == CMD_SIGN || tdata->options->cmd == CMD_ADD
		|| tdata->options->cmd == CMD_ATTACH) {
		u_char buf[] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		/*
		 * Update additional data size.
		 * Additional data size is located at offset 0x30 (from file beginning)
		 * and consist of 4 bytes (little-endian order).
		 */
		(void)BIO_seek(tdata->sign->outdata, 0x30);
		PUT_UINT32_LE(tdata->sign->len + tdata->sign->padlen, buf);
		BIO_write(tdata->sign->outdata, buf, 4);
	}
}

static int cab_verify_signed(TYPE_DATA *tdata)
{
	int i, ret = 1;
	PKCS7 *p7;
	STACK_OF(SIGNATURE) *signatures = sk_SIGNATURE_new_null();

	if (!tdata) {
		printf("Init error\n\n");
		goto out;
	}
	if (tdata->cab->header_size != 20) {
		printf("No signature found\n\n");
		goto out;
	}
	if (tdata->cab->sigpos == 0 || tdata->cab->siglen == 0
		|| tdata->cab->sigpos > tdata->cab->fileend) {
		printf("No signature found\n\n");
		goto out;
	}
	p7 = cab_extract_existing_pkcs7(tdata->options->indata, tdata->cab);
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
		ret &= cab_verify_pkcs7(tdata, signature);
	}
	printf("Number of verified signatures: %d\n", i);
out:
	sk_SIGNATURE_pop_free(signatures, signature_free);
	return ret;
}

static int cab_extract_signature(TYPE_DATA *tdata)
{
	int ret = 0;
	PKCS7 *sig;
	size_t written;

	(void)BIO_reset(tdata->sign->outdata);
	if (tdata->options->output_pkcs7) {
		sig = cab_extract_existing_pkcs7(tdata->options->indata, tdata->cab);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(tdata->sign->outdata, sig);
		PKCS7_free(sig);
	} else
		if (!BIO_write_ex(tdata->sign->outdata,
			tdata->options->indata + tdata->cab->sigpos,
			tdata->cab->siglen, &written) || written != tdata->cab->siglen)
			ret = 1; /* FAILED */
	return ret;
}

static int cab_remove_signature(TYPE_DATA *tdata)
{
	size_t i, written, len;
	uint32_t tmp;
	uint16_t nfolders, flags;
	char *buf = OPENSSL_malloc(SIZE_64K);

	/*
	 * u1 signature[4] 4643534D MSCF: 0-3
	 * u4 reserved1 00000000: 4-7
	 */
	BIO_write(tdata->sign->outdata, tdata->options->indata, 8);
	/* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
	tmp = GET_UINT32_LE(tdata->options->indata + 8) - 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(tdata->sign->outdata, buf, 4);
	/* u4 reserved2 00000000: 12-15 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 12, 4);
	/* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	tmp = GET_UINT32_LE(tdata->options->indata + 16) - 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(tdata->sign->outdata, buf, 4);
	/*
	 * u4 reserved3 00000000: 20-23
	 * u1 versionMinor 03: 24
	 * u1 versionMajor 01: 25
	 * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
	 * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
	 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 20, 10);
	/* u2 flags: 30-31 */
	flags = GET_UINT16_LE(tdata->options->indata + 30);
	/* coverity[result_independent_of_operands] only least significant byte is affected */
	PUT_UINT16_LE(flags & (FLAG_PREV_CABINET | FLAG_NEXT_CABINET), buf);
	BIO_write(tdata->sign->outdata, buf, 2);
	/*
	 * u2 setID must be the same for all cabinets in a set: 32-33
	 * u2 iCabinet - number of this cabinet file in a set: 34-35
	 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 32, 4);
	i = 60;
	cab_optional_names(flags, tdata->options->indata, tdata->sign->outdata, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(tdata->options->indata + 26);
	while (nfolders) {
		tmp = GET_UINT32_LE(tdata->options->indata + i);
		tmp -= 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(tdata->sign->outdata, buf, 4);
		BIO_write(tdata->sign->outdata, tdata->options->indata + i + 4, 4);
		i+=8;
		nfolders--;
	}
	OPENSSL_free(buf);
	/* Write what's left - the compressed data bytes */
	len = tdata->cab->fileend - tdata->cab->siglen - i;
	while (len > 0) {
		if (!BIO_write_ex(tdata->sign->outdata, tdata->options->indata + i, len, &written))
			return 1; /* FAILED */
		len -= written;
		i += written;
	}
	return 0; /* OK */
}

static int cab_prepare_signature(TYPE_DATA *tdata)
{
	PKCS7 *sig = NULL;

	/* Obtain a current signature from previously-signed file */
	if ((tdata->options->cmd == CMD_SIGN && tdata->options->nest)
		|| (tdata->options->cmd == CMD_ATTACH && tdata->options->nest)
		|| tdata->options->cmd == CMD_ADD) {
		tdata->sign->cursig = cab_extract_existing_pkcs7(tdata->options->indata, tdata->cab);
		if (!tdata->sign->cursig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		if (tdata->options->cmd == CMD_ADD)
			sig = tdata->sign->cursig;
	}
	if (tdata->cab->header_size == 20) {
		/* Strip current signature and modify header */
		if (!cab_modify_header(tdata))
			return 1; /* FAILED */
	} else {
		if (!cab_add_header(tdata))
			return 1; /* FAILED */
	}
	/* Obtain an existing signature or create a new one */
	if ((tdata->options->cmd == CMD_ATTACH) || (tdata->options->cmd == CMD_SIGN))
		sig = get_pkcs7(tdata);

	tdata->sign->sig = sig;
	return 0; /* OK */
}

static int cab_append_signature(TYPE_DATA *tdata)
{
	u_char *p = NULL;
	PKCS7 *outsig;

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
	BIO_write(tdata->sign->outdata, p, tdata->sign->len);
	/* pad (with 0's) asn1 blob to 8 byte boundary */
	if (tdata->sign->padlen > 0) {
		memset(p, 0, (size_t)tdata->sign->padlen);
		BIO_write(tdata->sign->outdata, p, tdata->sign->padlen);
	}
	OPENSSL_free(p);
	return 0; /* OK */
}

static void cab_free_data(TYPE_DATA *tdata)
{
	BIO_free_all(tdata->sign->hash);
	tdata->sign->hash = tdata->sign->outdata = NULL;
}

static void cab_cleanup_data(TYPE_DATA *tdata)
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
	unmap_file(tdata->options->indata, tdata->cab->fileend);
	PKCS7_free(tdata->sign->sig);
	if (tdata->options->cmd != CMD_ADD)
		PKCS7_free(tdata->sign->cursig);
	OPENSSL_free(tdata->sign);
	OPENSSL_free(tdata->cab);
	OPENSSL_free(tdata);
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

static PKCS7 *cab_get_sigfile(TYPE_DATA *tdata)
{
	PKCS7 *sig = NULL;
	uint32_t sigfilesize;
	char *insigdata;
	CAB_HEADER header;
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
		memset(&header, 0, sizeof(CAB_HEADER));
		header.fileend = sigfilesize;
		header.siglen = sigfilesize;
		header.sigpos = 0;
		sig = cab_extract_existing_pkcs7(insigdata, &header);
	}
	unmap_file(insigdata, sigfilesize);
	return sig; /* OK */
}

static PKCS7 *cab_create_signature(TYPE_DATA *tdata)
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

	if (tdata->options->jp >= 0)
		cab_add_jp_attribute(si, tdata->options->jp);

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
		sig = cab_get_sigfile(tdata);
		if (!sig) {
			printf("Unable to extract valid signature\n");
			return NULL; /* FAILED */
		}
	} else if (tdata->options->cmd == CMD_SIGN) {
		sig = cab_create_signature(tdata);
		if (!sig) {
			printf("Creating a new signature failed\n");
			return NULL; /* FAILED */
		}
	}
	return sig;
}

/* Compute a message digest value of the signed or unsigned CAB file */
int cab_calc_digest(char *indata, int mdtype, u_char *mdbuf, CAB_HEADER *header)
{
	uint32_t idx = 0, fileend, coffFiles;
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

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_write(bhash, indata, 4);
	/* u4 reserved1 00000000: 4-7 skipped */
	if (header->sigpos) {
		uint16_t nfolders, flags;
		uint32_t pos = 60;
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
		idx += 60;
		/* TODO */
		if (flags & FLAG_PREV_CABINET) {
			uint8_t byte;
			/* szCabinetPrev */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				pos++;
				idx++;
			} while (byte && pos < fileend);
			/* szDiskPrev */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				pos++;
				idx++;
			} while (byte && pos < fileend);
		}
		if (flags & FLAG_NEXT_CABINET) {
			uint8_t byte;
			/* szCabinetNext */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				pos++;
				idx++;
			} while (byte && pos < fileend);
			/* szDiskNext */
			do {
				byte = GET_UINT8_LE(indata + idx);
				BIO_write(bhash, indata + idx, 1);
				pos++;
				idx++;
			} while (byte && pos < fileend);
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
	} else {
		/* read what's left of the unsigned CAB file */
		coffFiles = 8;
	}
	/* (variable) ab - the compressed data bytes */
	if (!bio_hash_data(indata, bhash, idx, coffFiles, fileend)) {
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

static int cab_verify_pkcs7(TYPE_DATA *tdata, SIGNATURE *signature)
{
	int ret = 1, mdtype = -1;
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
		goto out;
	}
	if (!cab_calc_digest(tdata->options->indata, mdtype, cmdbuf, tdata->cab)) {
		printf("Failed to calculate message digest\n\n");
		goto out;
	}
	if (!compare_digests(mdbuf, cmdbuf, mdtype)) {
		printf("Signature verification: failed\n\n");
		goto out;
	}

	ret = verify_signature(tdata, signature);
out:
	if (ret)
		ERR_print_errors_fp(stdout);
	return ret;
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

static int cab_modify_header(TYPE_DATA *tdata)
{
	size_t i, written, len;
	uint16_t nfolders, flags;
	u_char buf[] = {0x00, 0x00};

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_write(tdata->sign->hash, tdata->options->indata, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 4, 4);
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
	BIO_write(tdata->sign->hash, tdata->options->indata + 8, 22);
	/* u2 flags: 30-31 */
	flags = GET_UINT16_LE(tdata->options->indata + 30);
	PUT_UINT16_LE(flags, buf);
	BIO_write(tdata->sign->hash, buf, 2);
	/* u2 setID must be the same for all cabinets in a set: 32-33 */
	BIO_write(tdata->sign->hash, tdata->options->indata + 32, 2);
	/*
	 * u2 iCabinet - number of this cabinet file in a set: 34-35
	 * u2 cbCFHeader: 36-37
	 * u1 cbCFFolder: 38
	 * u1 cbCFData: 39
	 * u16 abReserve: 40-55
	 * - Additional data offset: 44-47
	 * - Additional data size: 48-51
	 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 34, 22);
	/* u4 abReserve: 56-59 */
	BIO_write(tdata->sign->hash, tdata->options->indata + 56, 4);

	i = 60;
	cab_optional_names(flags, tdata->options->indata, tdata->sign->hash, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(tdata->options->indata + 26);
	while (nfolders) {
		BIO_write(tdata->sign->hash, tdata->options->indata + i, 8);
		i += 8;
		nfolders--;
	}
	/* Write what's left - the compressed data bytes */
	len = tdata->cab->sigpos - i;
	while (len > 0) {
		if (!BIO_write_ex(tdata->sign->hash, tdata->options->indata + i, len, &written))
			return 0; /* FAILED */
		len -= written;
		i += written;
	}
	return 1; /* OK */
}

static int cab_add_header(TYPE_DATA *tdata)
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
	BIO_write(tdata->sign->hash, tdata->options->indata, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 4, 4);
	/* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
	tmp = GET_UINT32_LE(tdata->options->indata + 8) + 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(tdata->sign->hash, buf, 4);
	/* u4 reserved2 00000000: 12-15 */
	BIO_write(tdata->sign->hash, tdata->options->indata + 12, 4);
	/* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	tmp = GET_UINT32_LE(tdata->options->indata + 16) + 24;
	PUT_UINT32_LE(tmp, buf + 4);
	BIO_write(tdata->sign->hash, buf + 4, 4);
	/*
	 * u4 reserved3 00000000: 20-23
	 * u1 versionMinor 03: 24
	 * u1 versionMajor 01: 25
	 * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
	 * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
	 */
	memcpy(buf + 4, tdata->options->indata + 20, 10);
	flags = GET_UINT16_LE(tdata->options->indata + 30);
	buf[4+10] = (char)flags | FLAG_RESERVE_PRESENT;
	/* u2 setID must be the same for all cabinets in a set: 32-33 */
	memcpy(buf + 16, tdata->options->indata + 32, 2);
	BIO_write(tdata->sign->hash, buf + 4, 14);
	/* u2 iCabinet - number of this cabinet file in a set: 34-35 */
	BIO_write(tdata->sign->outdata, tdata->options->indata + 34, 2);
	memcpy(cabsigned + 8, buf, 4);
	BIO_write(tdata->sign->outdata, cabsigned, 20);
	BIO_write(tdata->sign->hash, cabsigned+20, 4);

	i = 36;
	cab_optional_names(flags, tdata->options->indata, tdata->sign->hash, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(tdata->options->indata + 26);
	while (nfolders) {
		tmp += 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(tdata->sign->hash, buf, 4);
		BIO_write(tdata->sign->hash, tdata->options->indata + i + 4, 4);
		i += 8;
		nfolders--;
	}
	OPENSSL_free(buf);
	/* Write what's left - the compressed data bytes */
	len = tdata->cab->fileend - i;
	while (len > 0) {
		if (!BIO_write_ex(tdata->sign->hash, tdata->options->indata + i, len, &written))
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
