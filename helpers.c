/*
 * osslsigncode support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */

#include "osslsigncode.h"
#include "helpers.h"

/* Prototypes */
static int pkcs7_set_content_blob(PKCS7 *sig, PKCS7 *cursig);
static SpcSpOpusInfo *spc_sp_opus_info_create(FILE_FORMAT_CTX *ctx);
static int X509_attribute_chain_append_signature(STACK_OF(X509_ATTRIBUTE) **unauth_attr, u_char *p, int len);
static int spc_indirect_data_content_get(u_char **blob, int *len, FILE_FORMAT_CTX *ctx);
static int pkcs7_set_spc_indirect_data_content(PKCS7 *p7, BIO *hash, u_char *buf, int len);
static int pkcs7_signer_info_add_spc_sp_opus_info(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx);
static int pkcs7_signer_info_add_purpose(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx);
static int pkcs7_signer_info_add_signing_time(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx);

/*
 * Common functions
 */

/*
 * [in] infile
 * [returns] file size
 */
uint32_t get_file_size(const char *infile)
{
	int ret;
#ifdef _WIN32
	struct _stat64 st;
	ret = _stat64(infile, &st);
#else
	struct stat st;
	ret = stat(infile, &st);
#endif
	if (ret) {
		printf("Failed to open file: %s\n", infile);
		return 0;
	}

	if (st.st_size < 4) {
		printf("Unrecognized file type - file is too short: %s\n", infile);
		return 0;
	}
	if (st.st_size > UINT32_MAX) {
		printf("Unsupported file - too large: %s\n", infile);
		return 0;
	}
	return (uint32_t)st.st_size;
}

/*
 * [in] infile: starting address for the new mapping
 * [returns] pointer to the mapped area
 */
char *map_file(const char *infile, const size_t size)
{
	char *indata = NULL;
#ifdef WIN32
	HANDLE fhandle, fmap;
	(void)size;
	fhandle = CreateFile(infile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (fhandle == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	fmap = CreateFileMapping(fhandle, NULL, PAGE_READONLY, 0, 0, NULL);
	CloseHandle(fhandle);
	if (fmap == NULL) {
		return NULL;
	}
	indata = (char *)MapViewOfFile(fmap, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(fmap);
#else
#ifdef HAVE_SYS_MMAN_H
	int fd = open(infile, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}
	indata = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (indata == MAP_FAILED) {
		close(fd);
		return NULL;
	}
	close(fd);
#else
	printf("No file mapping function\n");
	return NULL;
#endif /* HAVE_SYS_MMAN_H */
#endif /* WIN32 */
	return indata;
}

/*
 * [in] indata: starting address space
 * [in] size: mapped area length
 * [returns] none
 */
void unmap_file(char *indata, const size_t size)
{
	if (!indata)
		return;
#ifdef WIN32
	(void)size;
	UnmapViewOfFile(indata);
#else
	munmap(indata, size);
#endif /* WIN32 */
}

/*
 * [in, out] si: PKCS7_SIGNER_INFO structure
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_signer_info_add_spc_sp_opus_info(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx)
{
	SpcSpOpusInfo *opus;
	ASN1_STRING *astr;
	int len;
	u_char *p = NULL;

	opus = spc_sp_opus_info_create(ctx);
	if ((len = i2d_SpcSpOpusInfo(opus, NULL)) <= 0
		|| (p = OPENSSL_malloc((size_t)len)) == NULL) {
		SpcSpOpusInfo_free(opus);
		return 0; /* FAILED */
	}
	i2d_SpcSpOpusInfo(opus, &p);
	p -= len;
	astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);
	OPENSSL_free(p);
	SpcSpOpusInfo_free(opus);
	return PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_SP_OPUS_INFO_OBJID),
			V_ASN1_SEQUENCE, astr);
}

/*
 * [in, out] si: PKCS7_SIGNER_INFO structure
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_signer_info_add_purpose(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx)
{
	static const u_char purpose_ind[] = {
		0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x01, 0x15
	};
	static const u_char purpose_comm[] = {
		0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x01, 0x16
	};
	ASN1_STRING *purpose = ASN1_STRING_new();

	if (ctx->options->comm) {
		ASN1_STRING_set(purpose, purpose_comm, sizeof purpose_comm);
	} else {
		ASN1_STRING_set(purpose, purpose_ind, sizeof purpose_ind);
	}
	return PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_STATEMENT_TYPE_OBJID),
			V_ASN1_SEQUENCE, purpose);
}

/*
 * Add a custom, non-trusted time to the PKCS7 structure to prevent OpenSSL
 * adding the _current_ time. This allows to create a deterministic signature
 * when no trusted timestamp server was specified, making osslsigncode
 * behaviour closer to signtool.exe (which doesn't include any non-trusted
 * time in this case.)
 * [in, out] si: PKCS7_SIGNER_INFO structure
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_signer_info_add_signing_time(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx)
{
	if (ctx->options->time == INVALID_TIME) /* -time option was not specified */
		return 1; /* SUCCESS */
	return PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime, V_ASN1_UTCTIME,
		ASN1_TIME_adj(NULL, ctx->options->time, 0, 0));
}

/*
 * Retrieve a decoded PKCS#7 struct corresponding to the signature
 * stored in the "sigin" file
 * CMD_ATTACH command specific
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
PKCS7 *pkcs7_get_sigfile(FILE_FORMAT_CTX *ctx)
{
	PKCS7 *p7 = NULL;
	uint32_t filesize;
	char *indata;
	BIO *bio;
	const char pemhdr[] = "-----BEGIN PKCS7-----";

	filesize = get_file_size(ctx->options->sigfile);
	if (!filesize) {
		return NULL; /* FAILED */
	}
	indata = map_file(ctx->options->sigfile, filesize);
	if (!indata) {
		printf("Failed to open file: %s\n", ctx->options->sigfile);
		return NULL; /* FAILED */
	}
	bio = BIO_new_mem_buf(indata, (int)filesize);
	if (filesize >= sizeof pemhdr && !memcmp(indata, pemhdr, sizeof pemhdr - 1)) {
		/* PEM format */
		p7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
	} else { /* DER format */
		p7 = d2i_PKCS7_bio(bio, NULL);
	}
	BIO_free_all(bio);
	unmap_file(indata, filesize);
	return p7;
}

/*
 * Allocate, set type, add content and return a new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
PKCS7 *pkcs7_create(FILE_FORMAT_CTX *ctx)
{
	int i, signer = -1;
	PKCS7 *p7;
	PKCS7_SIGNER_INFO *si = NULL;

	p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);

	if (ctx->options->cert != NULL) {
		/*
		 * the private key and corresponding certificate are parsed from the PKCS12
		 * structure or loaded from the security token, so we may omit to check
		 * the consistency of a private key with the public key in an X509 certificate
		 */
		si = PKCS7_add_signature(p7, ctx->options->cert, ctx->options->pkey,
			ctx->options->md);
		if (si == NULL)
			return NULL; /* FAILED */
	} else {
		/* find the signer's certificate located somewhere in the whole certificate chain */
		for (i=0; i<sk_X509_num(ctx->options->certs); i++) {
			X509 *signcert = sk_X509_value(ctx->options->certs, i);
			if (X509_check_private_key(signcert, ctx->options->pkey)) {
				si = PKCS7_add_signature(p7, signcert, ctx->options->pkey, ctx->options->md);
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

	if (!pkcs7_signer_info_add_purpose(si, ctx))
		return NULL; /* FAILED */

	if ((ctx->options->desc || ctx->options->url) &&
			!pkcs7_signer_info_add_spc_sp_opus_info(si, ctx)) {
		printf("Couldn't allocate memory for opus info\n");
		return NULL; /* FAILED */
	}
	PKCS7_content_new(p7, NID_pkcs7_data);

	/* add the signer's certificate */
	if (ctx->options->cert != NULL)
		PKCS7_add_certificate(p7, ctx->options->cert);
	if (signer != -1)
		PKCS7_add_certificate(p7, sk_X509_value(ctx->options->certs, signer));

	/* add the certificate chain */
	for (i=0; i<sk_X509_num(ctx->options->certs); i++) {
		if (i == signer)
			continue;
		PKCS7_add_certificate(p7, sk_X509_value(ctx->options->certs, i));
	}
	/* add all cross certificates */
	if (ctx->options->xcerts) {
		for (i=0; i<sk_X509_num(ctx->options->xcerts); i++)
			PKCS7_add_certificate(p7, sk_X509_value(ctx->options->xcerts, i));
	}
	/* add crls */
	if (ctx->options->crls) {
		for (i=0; i<sk_X509_CRL_num(ctx->options->crls); i++)
			PKCS7_add_crl(p7, sk_X509_CRL_value(ctx->options->crls, i));
	}
	return p7; /* OK */
}

/*
 * [in, out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [returns] 0 on error or 1 on success
 */
int add_indirect_data_object(PKCS7 *p7, BIO *hash, FILE_FORMAT_CTX *ctx)
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
		V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1)))
		return 0; /* FAILED */
	if (!pkcs7_set_data_content(p7, hash, ctx)) {
		printf("Signing failed\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

/*
 * [in, out] p7: new PKCS#7 signature
 * [in] cursig: current PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
int add_ms_ctl_object(PKCS7 *p7, PKCS7 *cursig)
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
	if (!pkcs7_set_content_blob(p7, cursig)) {
		printf("Signing failed\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

static int pkcs7_set_content_blob(PKCS7 *sig, PKCS7 *cursig)
{
	PKCS7 *contents;
	u_char *content;
	int seqhdrlen, content_length;
	BIO *sigbio;

	contents = cursig->d.sign->contents;
	seqhdrlen = asn1_simple_hdr_len(contents->d.other->value.sequence->data,
		contents->d.other->value.sequence->length);
	content = contents->d.other->value.sequence->data + seqhdrlen;
	content_length = contents->d.other->value.sequence->length - seqhdrlen;

	if ((sigbio = PKCS7_dataInit(sig, NULL)) == NULL) {
		printf("PKCS7_dataInit failed\n");
		return 0; /* FAILED */
	}
	BIO_write(sigbio, content, content_length);
	(void)BIO_flush(sigbio);
	if (!PKCS7_dataFinal(sig, sigbio)) {
		printf("PKCS7_dataFinal failed\n");
		return 0; /* FAILED */
	}
	BIO_free_all(sigbio);
	if (!PKCS7_set_content(sig, PKCS7_dup(contents))) {
		printf("PKCS7_set_content failed\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

/*
 * Add the new signature to the current signature as a nested signature:
 * new unauthorized SPC_NESTED_SIGNATURE_OBJID attribute
 * [out] cursig: current PKCS#7 signature
 * [in] p7: new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
int cursig_set_nested(PKCS7 *cursig, PKCS7 *p7, FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	int len = 0;
	PKCS7_SIGNER_INFO *si;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;

	if (!cursig)
		return 0; /* FAILED */
	signer_info = PKCS7_get_signer_info(cursig);
	if (!signer_info)
		return 0; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 0; /* FAILED */
	if (((len = i2d_PKCS7(p7, NULL)) <= 0) ||
		(p = OPENSSL_malloc((size_t)len)) == NULL)
		return 0; /* FAILED */
	i2d_PKCS7(p7, &p);
	p -= len;

	pkcs7_signer_info_add_signing_time(si, ctx);
	if (!X509_attribute_chain_append_signature(&(si->unauth_attr), p, len)) {
		OPENSSL_free(p);
		return 0; /* FAILED */
	}
	OPENSSL_free(p);
	return 1; /* OK */
}

/* Return the header length (tag and length octets) of the ASN.1 type
 * [in] p: ASN.1 data
 * [in] len: ASN.1 data length
 * [returns] header length
 */
int asn1_simple_hdr_len(const u_char *p, int len)
{
	if (len <= 2 || p[0] > 0x31)
		return 0;
	return (p[1]&0x80) ? (2 + (p[1]&0x7f)) : 2;
}

/*
 * [in, out] hash: BIO with message digest method
 * [in] indata: starting address space
 * [in] idx: offset
 * [in] fileend: the length of the hashed area
 * [returns] 0 on error or 1 on success
 */
int bio_hash_data(BIO *hash, char *indata, size_t idx, size_t fileend)
{
	while (idx < fileend) {
		size_t want, written;
		want = fileend - idx;
		if (want > SIZE_64K)
			want = SIZE_64K;
		if (!BIO_write_ex(hash, indata + idx, want, &written))
			return 0; /* FAILED */
		idx += written;
	}
	return 1; /* OK */
}

/*
 * [in] descript1, descript2: descriptions
 * [in] mdbuf: message digest
 * [in] len: message digest length
 * [returns] none
 */
void print_hash(const char *descript1, const char *descript2, const u_char *mdbuf, int len)
{
	char *hexbuf = NULL;
	int size, i, j = 0;

	size = 2 * len + 1;
	hexbuf = OPENSSL_malloc((size_t)size);
	for (i = 0; i < len; i++) {
#ifdef WIN32
		j += sprintf_s(hexbuf + j, size - j, "%02X", mdbuf[i]);
#else
		j += sprintf(hexbuf + j, "%02X", mdbuf[i]);
#endif /* WIN32 */
	}
	printf("%s: %s %s\n", descript1, hexbuf, descript2);
	OPENSSL_free(hexbuf);
}

/*
 * [in] p7: new PKCS#7 signature
 * [in] objid: Microsoft OID Authenticode
 * [returns] 0 on error or 1 on success
 */
int is_content_type(PKCS7 *p7, const char *objid)
{
	ASN1_OBJECT *indir_objid;
	int ret;

	indir_objid = OBJ_txt2obj(objid, 1);
	ret = p7 && PKCS7_type_is_signed(p7) &&
		!OBJ_cmp(p7->d.sign->contents->type, indir_objid) &&
		(p7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE ||
		p7->d.sign->contents->d.other->type == V_ASN1_OCTET_STRING);
	ASN1_OBJECT_free(indir_objid);
	return ret;
}

/*
 * [out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
int pkcs7_set_data_content(PKCS7 *p7, BIO *hash, FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	int len = 0;
	u_char *buf;

	if (!spc_indirect_data_content_get(&p, &len, ctx))
		return 0; /* FAILED */
	buf = OPENSSL_malloc(SIZE_64K);
	memcpy(buf, p, (size_t)len);
	OPENSSL_free(p);
	if (!pkcs7_set_spc_indirect_data_content(p7, hash, buf, len)) {
		OPENSSL_free(buf);
		return 0; /* FAILED */
	}
	OPENSSL_free(buf);

	return 1; /* OK */
}

/*
 * PE and CAB format specific
 * [in] none
 * [returns] pointer to SpcLink
 */
SpcLink *spc_link_obsolete_get(void)
{
	const u_char obsolete[] = {
		0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f,
		0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c,
		0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3e,
		0x00, 0x3e, 0x00, 0x3e
	};
	SpcLink *link = SpcLink_new();
	link->type = 2;
	link->value.file = SpcString_new();
	link->value.file->type = 0;
	link->value.file->value.unicode = ASN1_BMPSTRING_new();
	ASN1_STRING_set(link->value.file->value.unicode, obsolete, sizeof obsolete);
	return link;
}

/*
 * Retrieve a decoded PKCS#7 struct
 * [in] indata: mapped file
 * [in] sigpos: signature data offset
 * [in] siglen: signature data size
 * [returns] pointer to PKCS#7 structure
 */
PKCS7 *pkcs7_get(char *indata, uint32_t sigpos, uint32_t siglen)
{
	PKCS7 *p7 = NULL;
	const u_char *blob;

	blob = (u_char *)indata + sigpos;
	p7 = d2i_PKCS7(NULL, &blob, siglen);
	return p7;
}

/*
 * [in] mdbuf, cmdbuf: message digests
 * [in] mdtype: message digest algorithm type
 * [returns] 0 on error or 1 on success
 */
int compare_digests(u_char *mdbuf, u_char *cmdbuf, int mdtype)
{
	int mdlen = EVP_MD_size(EVP_get_digestbynid(mdtype));
	int mdok = !memcmp(mdbuf, cmdbuf, (size_t)mdlen);
	printf("Message digest algorithm  : %s\n", OBJ_nid2sn(mdtype));
	print_hash("Current message digest    ", "", mdbuf, mdlen);
	print_hash("Calculated message digest ", mdok ? "\n" : "    MISMATCH!!!\n", cmdbuf, mdlen);
	return mdok;
}

/*
 * Helper functions
 */

/*
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] pointer to SpcSpOpusInfo structure
 */
static SpcSpOpusInfo *spc_sp_opus_info_create(FILE_FORMAT_CTX *ctx)
{
	SpcSpOpusInfo *info = SpcSpOpusInfo_new();

	if (ctx->options->desc) {
		info->programName = SpcString_new();
		info->programName->type = 1;
		info->programName->value.ascii = ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->programName->value.ascii,
				ctx->options->desc, (int)strlen(ctx->options->desc));
	}
	if (ctx->options->url) {
		info->moreInfo = SpcLink_new();
		info->moreInfo->type = 0;
		info->moreInfo->value.url = ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->moreInfo->value.url,
				ctx->options->url, (int)strlen(ctx->options->url));
	}
	return info;
}

/*
 * [in, out] unauth_attr: unauthorized attributes list
 * [in] p: PKCS#7 data
 * [in] len: PKCS#7 data length
 * [returns] 0 on error or 1 on success
 */
static int X509_attribute_chain_append_signature(STACK_OF(X509_ATTRIBUTE) **unauth_attr, u_char *p, int len)
{
	X509_ATTRIBUTE *attr = NULL;
	int nid = OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID);

	if (*unauth_attr == NULL) {
		if ((*unauth_attr = sk_X509_ATTRIBUTE_new_null()) == NULL)
			return 0; /* FAILED */
	} else {
		/* try to find SPC_NESTED_SIGNATURE_OBJID attribute */
		int i;
		for (i = 0; i < sk_X509_ATTRIBUTE_num(*unauth_attr); i++) {
			attr = sk_X509_ATTRIBUTE_value(*unauth_attr, i);
			if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == nid) {
				/* append p to the V_ASN1_SEQUENCE */
				if (!X509_ATTRIBUTE_set1_data(attr, V_ASN1_SEQUENCE, p, len))
					return 0; /* FAILED */
				return 1; /* OK */
			}
		}
	}
	/* create new unauthorized SPC_NESTED_SIGNATURE_OBJID attribute */
	attr = X509_ATTRIBUTE_create_by_NID(NULL, nid, V_ASN1_SEQUENCE, p, len);
	if (!attr)
		return 0; /* FAILED */
	if (!sk_X509_ATTRIBUTE_push(*unauth_attr, attr)) {
		X509_ATTRIBUTE_free(attr);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

/*
 * [out] blob: SpcIndirectDataContent data
 * [out] len: SpcIndirectDataContent data length
 * [in] ctx: FILE_FORMAT_CTX structure
 * [returns] 0 on error or 1 on success
 */
static int spc_indirect_data_content_get(u_char **blob, int *len, FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	int hashlen, l = 0;
	void *hash;
	SpcIndirectDataContent *idc = SpcIndirectDataContent_new();

	idc->data->value = ASN1_TYPE_new();
	idc->data->value->type = V_ASN1_SEQUENCE;
	idc->data->value->value.sequence = ASN1_STRING_new();
	idc->data->type = ctx->format->get_data_blob(ctx, &p, &l);
	idc->data->value->value.sequence->data = p;
	idc->data->value->value.sequence->length = l;
	idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(ctx->options->md));
	idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
	idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

	hashlen = EVP_MD_size(ctx->options->md);
	hash = OPENSSL_malloc((size_t)hashlen);
	memset(hash, 0, (size_t)hashlen);
	ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashlen);
	OPENSSL_free(hash);

	*len  = i2d_SpcIndirectDataContent(idc, NULL);
	*blob = OPENSSL_malloc((size_t)*len);
	p = *blob;
	i2d_SpcIndirectDataContent(idc, &p);
	SpcIndirectDataContent_free(idc);
	*len -= EVP_MD_size(ctx->options->md);
	return 1; /* OK */
}

/*
 * Replace the data part with the MS Authenticode spcIndirectDataContent blob
 * [out] p7: new PKCS#7 signature
 * [in] hash: message digest BIO
 * [in] blob: SpcIndirectDataContent data
 * [in] len: SpcIndirectDataContent data length
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_set_spc_indirect_data_content(PKCS7 *p7, BIO *hash, u_char *buf, int len)
{
	u_char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen, seqhdrlen;
	BIO *bio;
	PKCS7 *td7;

	mdlen = BIO_gets(hash, (char*)mdbuf, EVP_MAX_MD_SIZE);
	memcpy(buf+len, mdbuf, (size_t)mdlen);
	seqhdrlen = asn1_simple_hdr_len(buf, len);

	if ((bio = PKCS7_dataInit(p7, NULL)) == NULL) {
		printf("PKCS7_dataInit failed\n");
		return 0; /* FAILED */
	}
	BIO_write(bio, buf + seqhdrlen, len - seqhdrlen + mdlen);
	(void)BIO_flush(bio);

	if (!PKCS7_dataFinal(p7, bio)) {
		printf("PKCS7_dataFinal failed\n");
		return 0; /* FAILED */
	}
	BIO_free_all(bio);

	td7 = PKCS7_new();
	td7->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	td7->d.other = ASN1_TYPE_new();
	td7->d.other->type = V_ASN1_SEQUENCE;
	td7->d.other->value.sequence = ASN1_STRING_new();
	ASN1_STRING_set(td7->d.other->value.sequence, buf, len+mdlen);
	if (!PKCS7_set_content(p7, td7)) {
		PKCS7_free(td7);
		printf("PKCS7_set_content failed\n");
		return 0; /* FAILED */
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
