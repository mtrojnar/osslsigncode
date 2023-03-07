/*
 * osslsigncode support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */

#include "osslsigncode.h"
#include "helpers.h"

/* Prototypes */
static SpcSpOpusInfo *spc_sp_opus_info_create(FILE_FORMAT_CTX *ctx);
static int X509_attribute_chain_append_signature(STACK_OF(X509_ATTRIBUTE) **unauth_attr, u_char *p, int len);
static int spc_indirect_data_content_get(u_char **blob, int *len, FILE_FORMAT_CTX *ctx);
static int pkcs7_set_spc_indirect_data_content(PKCS7 *sig, FILE_FORMAT_CTX *ctx, u_char *buf, int len);
static void signature_get_signed_attributes(SIGNATURE *signature,
	STACK_OF(X509_ATTRIBUTE) *auth_attr);
static void signature_get_unsigned_attributes(SIGNATURE *signature,
	STACK_OF(SIGNATURE) **signatures, STACK_OF(X509_ATTRIBUTE) *unauth_attr,
	PKCS7 *p7, int allownest);
static time_t asn1_get_time_t(const ASN1_TIME *s);
static time_t si_get_time(PKCS7_SIGNER_INFO *si);
static time_t cms_get_time(CMS_ContentInfo *cms);
static CMS_ContentInfo *cms_get_timestamp(PKCS7_SIGNED *p7_signed,
	PKCS7_SIGNER_INFO *countersignature);
static void signature_free(SIGNATURE *signature);

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
int pkcs7_signer_info_add_spc_sp_opus_info(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx)
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
 * [in] ctx: structure holds all input and output data
 * [returns] 0 on error or 1 on success
 */
int pkcs7_signer_info_add_purpose(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx)
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
 * [in] ctx: structure holds all input and output data
 * [returns] 0 on error or 1 on success
 */
int pkcs7_signer_info_add_signing_time(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx)
{
	if (ctx->options->time == INVALID_TIME) /* -time option was not specified */
		return 1; /* SUCCESS */
	return PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime, V_ASN1_UTCTIME,
		ASN1_TIME_adj(NULL, ctx->options->time, 0, 0));
}

/*
 * Add the current signature to the new signature as a nested signature:
 * new unauthorized SPC_NESTED_SIGNATURE_OBJID attribute
 * [in, out] ctx: structure holds all input and output data
 * [returns] 0 on error or 1 on success
 */
int set_nested_signature(FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	int len = 0;
	PKCS7_SIGNER_INFO *si;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;

	signer_info = PKCS7_get_signer_info(ctx->sign->cursig);
	if (!signer_info)
		return 0; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 0; /* FAILED */
	if (((len = i2d_PKCS7(ctx->sign->sig, NULL)) <= 0) ||
		(p = OPENSSL_malloc((size_t)len)) == NULL)
		return 0; /* FAILED */
	i2d_PKCS7(ctx->sign->sig, &p);
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
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	int i, j = 0;

	if (len > EVP_MAX_MD_SIZE) {
		printf("Invalid message digest size\n");
		return;
	}
	for (i = 0; i < len; i++) {
#ifdef WIN32
		int size = EVP_MAX_MD_SIZE*2 + 1;
		j += sprintf_s(hexbuf + j, size - j, "%02X", mdbuf[i]);
#else
		j += sprintf(hexbuf + j, "%02X", mdbuf[i]);
#endif /* WIN32 */
	}
	printf("%s: %s %s\n", descript1, hexbuf, descript2);
}

/*
 * [in] p7: PKCS#7 signedData structure
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
 * [out] p7: PKCS#7 signedData structure
 * [in] ctx: structure holds all input and output data
 * [returns] 0 on error or 1 on success
 */
int pkcs7_set_data_content(PKCS7 *p7, FILE_FORMAT_CTX *ctx)
{
	u_char *p = NULL;
	int len = 0;
	u_char *buf;

	if (!spc_indirect_data_content_get(&p, &len, ctx))
		return 0; /* FAILED */
	buf = OPENSSL_malloc(SIZE_64K);
	memcpy(buf, p, (size_t)len);
	OPENSSL_free(p);
	if (!pkcs7_set_spc_indirect_data_content(p7, ctx, buf, len)) {
		OPENSSL_free(buf);
		return 0; /* FAILED */
	}
	OPENSSL_free(buf);

	return 1; /* OK */
}

/*
 * Create new SIGNATURE structure, get signed and unsigned attributes,
 * insert this signature to signature list
 * [in, out] signatures: signature list
 * [in] p7: PKCS#7 signedData structure
 * [in] allownest: allow nested signature switch
 * [returns] 0 on error or 1 on success
 */
int signature_list_append_pkcs7(STACK_OF(SIGNATURE) **signatures, PKCS7 *p7, int allownest)
{
	SIGNATURE *signature = NULL;
	PKCS7_SIGNER_INFO *si;
	STACK_OF(X509_ATTRIBUTE) *auth_attr, *unauth_attr;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info = PKCS7_get_signer_info(p7);

	if (!signer_info)
		return 0; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 0; /* FAILED */

	signature = OPENSSL_malloc(sizeof(SIGNATURE));
	signature->p7 = p7;
	signature->md_nid = OBJ_obj2nid(si->digest_alg->algorithm);
	signature->digest = NULL;
	signature->signtime = INVALID_TIME;
	signature->url = NULL;
	signature->desc = NULL;
	signature->purpose = NULL;
	signature->level = NULL;
	signature->timestamp = NULL;
	signature->time = INVALID_TIME;
	signature->blob = NULL;

	auth_attr = PKCS7_get_signed_attributes(si);  /* cont[0] */
	if (auth_attr)
		signature_get_signed_attributes(signature, auth_attr);

	unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
	if (unauth_attr)
		signature_get_unsigned_attributes(signature, signatures, unauth_attr, p7, allownest);

	if (!sk_SIGNATURE_unshift(*signatures, signature)) {
		printf("Failed to insert signature\n");
		signature_free(signature);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

/*
 * [in] signatures: signature list
 * [returns] none
 */
void signature_list_free(STACK_OF(SIGNATURE) *signatures)
{
	sk_SIGNATURE_pop_free(signatures, signature_free);
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
 * [out] p7: PKCS#7 signedData structure
 * [in] ctx: FILE_FORMAT_CTX structure
 * [in] blob: SpcIndirectDataContent data
 * [in] len: SpcIndirectDataContent data length
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_set_spc_indirect_data_content(PKCS7 *p7, FILE_FORMAT_CTX *ctx, u_char *buf, int len)
{
	u_char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen, seqhdrlen;
	BIO *bio;
	PKCS7 *td7;

	mdlen = BIO_gets(ctx->sign->hash, (char*)mdbuf, EVP_MAX_MD_SIZE);
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
 * [out] signature: structure for authenticode and time stamping
 * [in] auth_attr: signed attributes list
 * [returns] none
 */
static void signature_get_signed_attributes(SIGNATURE *signature,
	STACK_OF(X509_ATTRIBUTE) *auth_attr)
{
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	char object_txt[128];
	const u_char *data;
	int i;

	for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
		attr = X509at_get_attr(auth_attr, i);
		object = X509_ATTRIBUTE_get0_object(attr);
		if (object == NULL)
			continue;
		object_txt[0] = 0x00;
		OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
		if (!strcmp(object_txt, PKCS9_MESSAGE_DIGEST)) {
			/* PKCS#9 message digest - Policy OID: 1.2.840.113549.1.9.4 */
			signature->digest  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_OCTET_STRING, NULL);
		} else if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
			/* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
			ASN1_UTCTIME *time;
			time = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
			signature->signtime = asn1_get_time_t(time);
		} else if (!strcmp(object_txt, SPC_SP_OPUS_INFO_OBJID)) {
			/* Microsoft OID: 1.3.6.1.4.1.311.2.1.12 */
			SpcSpOpusInfo *opus;
			value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			data = ASN1_STRING_get0_data(value);
			opus = d2i_SpcSpOpusInfo(NULL, &data, ASN1_STRING_length(value));
			if (opus == NULL)
				continue;
			if (opus->moreInfo && opus->moreInfo->type == 0)
				signature->url = OPENSSL_strdup((char *)opus->moreInfo->value.url->data);
			if (opus->programName) {
				if (opus->programName->type == 0) {
					u_char *desc;
					int len = ASN1_STRING_to_UTF8(&desc, opus->programName->value.unicode);
					if (len >= 0) {
						signature->desc = OPENSSL_strndup((char *)desc, (size_t)len);
						OPENSSL_free(desc);
					}
				} else {
					signature->desc = OPENSSL_strdup((char *)opus->programName->value.ascii->data);
				}
			}
			SpcSpOpusInfo_free(opus);
		} else if (!strcmp(object_txt, SPC_STATEMENT_TYPE_OBJID)) {
			/* Microsoft OID: 1.3.6.1.4.1.311.2.1.11 */
			value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			signature->purpose = ASN1_STRING_get0_data(value);
		} else if (!strcmp(object_txt, MS_JAVA_SOMETHING)) {
			/* Microsoft OID: 1.3.6.1.4.1.311.15.1 */
			value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			signature->level = ASN1_STRING_get0_data(value);
		}
	}
}

/*
 * [in, out] signatures: signature list
 * [out] signature: structure for authenticode and time stamping
 * [in] unauth_attr: unauthorized attributes list
 * [in] p7: PKCS#7 signedData structure
 * [in] allownest: allow nested signature switch
 * [returns] none
 */
static void signature_get_unsigned_attributes(SIGNATURE *signature,
	STACK_OF(SIGNATURE) **signatures, STACK_OF(X509_ATTRIBUTE) *unauth_attr,
	PKCS7 *p7, int allownest)
{
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	char object_txt[128];
	const u_char *data;
	int i, j;

	for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
		attr = X509at_get_attr(unauth_attr, i);
		object = X509_ATTRIBUTE_get0_object(attr);
		if (object == NULL)
			continue;
		object_txt[0] = 0x00;
		OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
		if (!strcmp(object_txt, PKCS9_COUNTER_SIGNATURE)) {
			/* Authenticode Timestamp - Policy OID: 1.2.840.113549.1.9.6 */
			PKCS7_SIGNER_INFO *countersi;
			CMS_ContentInfo *timestamp = NULL;
			time_t time;
			value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			data = ASN1_STRING_get0_data(value);
			countersi = d2i_PKCS7_SIGNER_INFO(NULL, &data, ASN1_STRING_length(value));
			if (countersi == NULL) {
				printf("Error: Authenticode Timestamp could not be decoded correctly\n");
				ERR_print_errors_fp(stdout);
				continue;
			}
			time = si_get_time(countersi);
			if (time != INVALID_TIME) {
				timestamp = cms_get_timestamp(p7->d.sign, countersi);
				if (timestamp) {
					signature->time = time;
					signature->timestamp = timestamp;
				} else {
					printf("Error: Corrupt Authenticode Timestamp embedded content\n");
				}
			} else {
				printf("Error: PKCS9_TIMESTAMP_SIGNING_TIME attribute not found\n");
				PKCS7_SIGNER_INFO_free(countersi);
			}
		} else if (!strcmp(object_txt, SPC_RFC3161_OBJID)) {
			/* RFC3161 Timestamp - Policy OID: 1.3.6.1.4.1.311.3.3.1 */
			CMS_ContentInfo *timestamp = NULL;
			time_t time;
			value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			data = ASN1_STRING_get0_data(value);
			timestamp = d2i_CMS_ContentInfo(NULL, &data, ASN1_STRING_length(value));
			if (timestamp == NULL) {
				printf("Error: RFC3161 Timestamp could not be decoded correctly\n");
				ERR_print_errors_fp(stdout);
				continue;
			}
			time = cms_get_time(timestamp);
			if (time != INVALID_TIME) {
				signature->time = time;
				signature->timestamp = timestamp;
			} else {
				printf("Error: Corrupt RFC3161 Timestamp embedded content\n");
				CMS_ContentInfo_free(timestamp);
				ERR_print_errors_fp(stdout);
			}
		} else if (allownest && !strcmp(object_txt, SPC_NESTED_SIGNATURE_OBJID)) {
			/* Nested Signature - Policy OID: 1.3.6.1.4.1.311.2.4.1 */
			PKCS7 *nested;
			for (j=0; j<X509_ATTRIBUTE_count(attr); j++) {
				value = X509_ATTRIBUTE_get0_data(attr, j, V_ASN1_SEQUENCE, NULL);
				if (value == NULL)
					continue;
				data = ASN1_STRING_get0_data(value);
				nested = d2i_PKCS7(NULL, &data, ASN1_STRING_length(value));
				if (nested)
					if (!signature_list_append_pkcs7(signatures, nested, 0)) {
						printf("Failed to append signature list\n\n");
						PKCS7_free(nested);
					}
			}
		} else if (!strcmp(object_txt, SPC_UNAUTHENTICATED_DATA_BLOB_OBJID)) {
			/* Unauthenticated Data Blob - Policy OID: 1.3.6.1.4.1.42921.1.2.1 */
			signature->blob = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTF8STRING, NULL);
		} else
			printf("Unsupported Policy OID: %s\n\n", object_txt);
	}
}

static time_t asn1_get_time_t(const ASN1_TIME *s)
{
	struct tm tm;

	if ((s == NULL) || (!ASN1_TIME_check(s))) {
		return INVALID_TIME;
	}
	if (ASN1_TIME_to_tm(s, &tm)) {
#ifdef _WIN32
		return _mkgmtime(&tm);
#else
		return timegm(&tm);
#endif
	} else {
		return INVALID_TIME;
	}
}

static time_t si_get_time(PKCS7_SIGNER_INFO *si)
{
	STACK_OF(X509_ATTRIBUTE) *auth_attr;
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_UTCTIME *time = NULL;
	time_t posix_time;
	char object_txt[128];
	int i;

	auth_attr = PKCS7_get_signed_attributes(si);  /* cont[0] */
	if (auth_attr)
		for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
			attr = X509at_get_attr(auth_attr, i);
			object = X509_ATTRIBUTE_get0_object(attr);
			if (object == NULL)
				return INVALID_TIME; /* FAILED */
			object_txt[0] = 0x00;
			OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
			if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
				/* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
				time = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
			}
		}
	posix_time = asn1_get_time_t(time);
	return posix_time;
}

static time_t cms_get_time(CMS_ContentInfo *cms)
{
	ASN1_OCTET_STRING **pos;
	const u_char *p = NULL;
	TimeStampToken *token = NULL;
	ASN1_GENERALIZEDTIME *asn1_time = NULL;
	time_t posix_time = INVALID_TIME;

	pos  = CMS_get0_content(cms);
	if (pos != NULL && *pos != NULL) {
		p = (*pos)->data;
		token = d2i_TimeStampToken(NULL, &p, (*pos)->length);
		if (token) {
			asn1_time = token->time;
			posix_time = asn1_get_time_t(asn1_time);
			TimeStampToken_free(token);
		}
	}
	return posix_time;
}

/*
 * Create new CMS_ContentInfo struct for Authenticode Timestamp.
 * This struct does not contain any TimeStampToken as specified in RFC 3161.
 */
static CMS_ContentInfo *cms_get_timestamp(PKCS7_SIGNED *p7_signed,
	PKCS7_SIGNER_INFO *countersignature)
{
	CMS_ContentInfo *cms = NULL;
	PKCS7_SIGNER_INFO *si;
	PKCS7 *p7 = NULL, *content = NULL;
	u_char *p = NULL;
	const u_char *q;
	int i, len = 0;

	p7 = PKCS7_new();
	si = sk_PKCS7_SIGNER_INFO_value(p7_signed->signer_info, 0);
	if (si == NULL)
		goto out;

	/* Create new signed PKCS7 timestamp structure. */
	if (!PKCS7_set_type(p7, NID_pkcs7_signed))
		goto out;
	if (!PKCS7_add_signer(p7, countersignature))
		goto out;
	for (i = 0; i < sk_X509_num(p7_signed->cert); i++) {
		if (!PKCS7_add_certificate(p7, sk_X509_value(p7_signed->cert, i)))
			goto out;
	}

	/* Create new encapsulated NID_id_smime_ct_TSTInfo content. */
	content = PKCS7_new();
	content->d.other = ASN1_TYPE_new();
	content->type = OBJ_nid2obj(NID_id_smime_ct_TSTInfo);
	ASN1_TYPE_set1(content->d.other, V_ASN1_OCTET_STRING, si->enc_digest);
	/* Add encapsulated content to signed PKCS7 timestamp structure:
	   p7->d.sign->contents = content */
	if (!PKCS7_set_content(p7, content)) {
		PKCS7_free(content);
		goto out;
	}

	/* Convert PKCS7 into CMS_ContentInfo */
	if (((len = i2d_PKCS7(p7, NULL)) <= 0) || (p = OPENSSL_malloc((size_t)len)) == NULL) {
		printf("Failed to convert pkcs7: %d\n", len);
		goto out;
	}
	len = i2d_PKCS7(p7, &p);
	p -= len;
	q = p;
	cms = d2i_CMS_ContentInfo(NULL, &q, len);
	OPENSSL_free(p);

out:
	if (!cms)
		ERR_print_errors_fp(stdout);
	PKCS7_free(p7);
	return cms;
}

static void signature_free(SIGNATURE *signature)
{
	if (signature->timestamp) {
		CMS_ContentInfo_free(signature->timestamp);
		ERR_clear_error();
	}
	PKCS7_free(signature->p7);
	/* If memory has not been allocated nothing is done */
	OPENSSL_free(signature->url);
	OPENSSL_free(signature->desc);
	OPENSSL_free(signature);
}

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
