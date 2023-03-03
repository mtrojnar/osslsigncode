/*
 * osslsigncode support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */

#include "osslsigncode.h"
#include "helpers.h"

/*
 * $ echo -n 3006030200013000 | xxd -r -p | openssl asn1parse -i -inform der
 * 0:d=0  hl=2 l=   6 cons: SEQUENCE
 * 2:d=1  hl=2 l=   2 prim:  BIT STRING
 * 6:d=1  hl=2 l=   0 cons:  SEQUENCE
*/
const u_char java_attrs_low[] = {
	0x30, 0x06, 0x03, 0x02, 0x00, 0x01, 0x30, 0x00
};

/*
 * $ echo -n 300c060a2b060104018237020115 | xxd -r -p | openssl asn1parse -i -inform der
 * 0:d=0  hl=2 l=  12 cons: SEQUENCE
 * 2:d=1  hl=2 l=  10 prim:  OBJECT     :Microsoft Individual Code Signing
*/
const u_char purpose_ind[] = {
	0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
	0x01, 0x82, 0x37, 0x02, 0x01, 0x15
};

/*
 * $ echo -n 300c060a2b060104018237020116 | xxd -r -p | openssl asn1parse -i -inform der
 * 0:d=0  hl=2 l=  12 cons: SEQUENCE
 * 2:d=1  hl=2 l=  10 prim:  OBJECT     :Microsoft Commercial Code Signing
*/
const u_char purpose_comm[] = {
	0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
	0x01, 0x82, 0x37, 0x02, 0x01, 0x16
};

/* Prototypes */
static SpcSpOpusInfo *spc_sp_opus_info_create(TYPE_DATA *tdata);
static int X509_attribute_chain_append_signature(STACK_OF(X509_ATTRIBUTE) **unauth_attr, u_char *p, int len);
static int spc_indirect_data_content_get(u_char **blob, int *len, TYPE_DATA *tdata);
static int pkcs7_set_spc_indirect_data_content(PKCS7 *sig, TYPE_DATA *tdata, u_char *buf, int len);
static X509 *find_signer(PKCS7 *p7, char *leafhash, int *leafok);
static int print_certs(PKCS7 *p7);
static int print_cert(X509 *cert, int i);
static char *get_clrdp_url(X509 *cert);
static int verify_timestamp(SIGNATURE *signature, TYPE_DATA *tdata);
static int verify_authenticode(SIGNATURE *signature, TYPE_DATA *tdata, X509 *signer);
static void signature_get_signed_attributes(SIGNATURE *signature,
	STACK_OF(X509_ATTRIBUTE) *auth_attr);
static void signature_get_unsigned_attributes(SIGNATURE *signature,
	STACK_OF(SIGNATURE) **signatures, STACK_OF(X509_ATTRIBUTE) *unauth_attr,
	PKCS7 *p7, int allownest);
static int print_attributes(SIGNATURE *signature, int verbose);
static int verify_leaf_hash(X509 *leaf, const char *leafhash);
static int load_file_lookup(X509_STORE *store, char *certs);
static int set_store_time(X509_STORE *store, time_t time);
static int verify_crl(char *ca_file, char *crl_file, STACK_OF(X509_CRL) *crls,
	X509 *signer, STACK_OF(X509) *chain);
static int TST_verify(CMS_ContentInfo *timestamp, PKCS7_SIGNER_INFO *si);
static int asn1_print_time(const ASN1_TIME *time);
static int print_time_t(const time_t time);
static time_t asn1_get_time_t(const ASN1_TIME *s);
static time_t si_get_time(PKCS7_SIGNER_INFO *si);
static time_t cms_get_time(CMS_ContentInfo *cms);
static int verify_callback(int ok, X509_STORE_CTX *ctx);
static int load_crlfile_lookup(X509_STORE *store, char *certs, char *crl);
static int cms_print_timestamp(CMS_ContentInfo *cms, time_t time);
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
 * [in] tdata: TYPE_DATA structure
 * [returns] 0 on error or 1 on success
 */
int pkcs7_signer_info_add_spc_sp_opus_info(PKCS7_SIGNER_INFO *si, TYPE_DATA *tdata)
{
	SpcSpOpusInfo *opus;
	ASN1_STRING *astr;
	int len;
	u_char *p = NULL;

	opus = spc_sp_opus_info_create(tdata);
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
 * [in] tdata: TYPE_DATA structure
 * [returns] 0 on error or 1 on success
 */
int pkcs7_signer_info_add_purpose(PKCS7_SIGNER_INFO *si, TYPE_DATA *tdata)
{
	ASN1_STRING *purpose = ASN1_STRING_new();

	if (tdata->options->comm) {
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
 * [in] tdata: TYPE_DATA structure
 * [returns] 0 on error or 1 on success
 */
int pkcs7_signer_info_add_signing_time(PKCS7_SIGNER_INFO *si, TYPE_DATA *tdata)
{
	if (tdata->options->time == INVALID_TIME) /* -time option was not specified */
		return 1; /* SUCCESS */
	return PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime, V_ASN1_UTCTIME,
		ASN1_TIME_adj(NULL, tdata->options->time, 0, 0));
}

/*
 * Add the current signature to the new signature as a nested signature:
 * new unauthorized SPC_NESTED_SIGNATURE_OBJID attribute
 * [in, out] tdata: TYPE_DATA structure
 * [returns] 0 on error or 1 on success
 */
int set_nested_signature(TYPE_DATA *tdata)
{
	u_char *p = NULL;
	int len = 0;
	PKCS7_SIGNER_INFO *si;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;

	signer_info = PKCS7_get_signer_info(tdata->sign->cursig);
	if (!signer_info)
		return 0; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 0; /* FAILED */
	if (((len = i2d_PKCS7(tdata->sign->sig, NULL)) <= 0) ||
		(p = OPENSSL_malloc((size_t)len)) == NULL)
		return 0; /* FAILED */
	i2d_PKCS7(tdata->sign->sig, &p);
	p -= len;

	pkcs7_signer_info_add_signing_time(si, tdata);
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
 * [in] p7:  PKCS#7 structure
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
 * [out] sig: PKCS#7 structure
 * [in] tdata: TYPE_DATA structure
 * [returns] 0 on error or 1 on success
 */
int pkcs7_set_data_content(PKCS7 *sig, TYPE_DATA *tdata)
{
	u_char *p = NULL;
	int len = 0;
	u_char *buf;

	if (!spc_indirect_data_content_get(&p, &len, tdata))
		return 0; /* FAILED */
	buf = OPENSSL_malloc(SIZE_64K);
	memcpy(buf, p, (size_t)len);
	OPENSSL_free(p);
	if (!pkcs7_set_spc_indirect_data_content(sig, tdata, buf, len)) {
		OPENSSL_free(buf);
		return 0; /* FAILED */
	}
	OPENSSL_free(buf);

	return 1; /* OK */
}

/*
 * [in] tdata: TYPE_DATA structure
 * [in] signature: SIGNATURE structure
 * [returns] 1 on error or 0 on success
 */
int verify_signature(TYPE_DATA *tdata, SIGNATURE *signature)
{
	int leafok = 0, verok;
	X509 *signer;
	char *url;

	signer = find_signer(signature->p7, tdata->options->leafhash, &leafok);
	if (!signer) {
		printf("Find signer error\n");
		return 1; /* FAILED */
	}
	if (!print_certs(signature->p7))
		printf("Print certs error\n");
	if (!print_attributes(signature, tdata->options->verbose))
		printf("Print attributes error\n");
	if (tdata->options->leafhash != NULL) {
		printf("\nLeaf hash match: %s\n", leafok ? "ok" : "failed");
		if (!leafok) {
			printf("Signature verification: failed\n\n");
			return 1; /* FAILED */
		}
	}
	if (tdata->options->catalog)
		printf("\nFile is signed in catalog: %s\n", tdata->options->catalog);
	printf("\nCAfile: %s\n", tdata->options->cafile);
	if (tdata->options->crlfile)
		printf("CRLfile: %s\n", tdata->options->crlfile);
	if (tdata->options->tsa_cafile)
		printf("TSA's certificates file: %s\n", tdata->options->tsa_cafile);
	if (tdata->options->tsa_crlfile)
		printf("TSA's CRL file: %s\n", tdata->options->tsa_crlfile);
	url = get_clrdp_url(signer);
	if (url) {
		printf("CRL distribution point: %s\n", url);
		OPENSSL_free(url);
	}

	if (signature->timestamp) {
		if (!tdata->options->ignore_timestamp) {
			int timeok = verify_timestamp(signature, tdata);
			printf("Timestamp Server Signature verification: %s\n", timeok ? "ok" : "failed");
			if (!timeok) {
				signature->time = INVALID_TIME;
			}
		} else {
			printf("\nTimestamp Server Signature verification is disabled\n\n");
			signature->time = INVALID_TIME;
		}
	} else
		printf("\nTimestamp is not available\n\n");
	verok = verify_authenticode(signature, tdata, signer);
	printf("Signature verification: %s\n\n", verok ? "ok" : "failed");
	if (!verok)
		return 1; /* FAILED */

	return 0; /* OK */
}

/*
 * Create new SIGNATURE structure, get signed and unsigned attributes,
 * insert this signature to signature list
 * [in, out] signatures: signature list
 * [in] p7: PKCS#7 structure
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
 * [in] tdata: TYPE_DATA structure
 * [returns] pointer to SpcSpOpusInfo structure
 */
static SpcSpOpusInfo *spc_sp_opus_info_create(TYPE_DATA *tdata)
{
	SpcSpOpusInfo *info = SpcSpOpusInfo_new();

	if (tdata->options->desc) {
		info->programName = SpcString_new();
		info->programName->type = 1;
		info->programName->value.ascii = ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->programName->value.ascii,
				tdata->options->desc, (int)strlen(tdata->options->desc));
	}
	if (tdata->options->url) {
		info->moreInfo = SpcLink_new();
		info->moreInfo->type = 0;
		info->moreInfo->value.url = ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->moreInfo->value.url,
				tdata->options->url, (int)strlen(tdata->options->url));
	}
	return info;
}

/*
 * [in, out] unauth_attr: pointer to STACK_OF(X509_ATTRIBUTE) structure
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
 * [in] tdata: TYPE_DATA structure
 * [returns] 0 on error or 1 on success
 */
static int spc_indirect_data_content_get(u_char **blob, int *len, TYPE_DATA *tdata)
{
	u_char *p = NULL;
	int hashlen, l = 0;
	void *hash;
	SpcIndirectDataContent *idc = SpcIndirectDataContent_new();

	idc->data->value = ASN1_TYPE_new();
	idc->data->value->type = V_ASN1_SEQUENCE;
	idc->data->value->value.sequence = ASN1_STRING_new();
	idc->data->type = tdata->format->get_data_blob(tdata, &p, &l);
	idc->data->value->value.sequence->data = p;
	idc->data->value->value.sequence->length = l;
	idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(tdata->options->md));
	idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
	idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

	hashlen = EVP_MD_size(tdata->options->md);
	hash = OPENSSL_malloc((size_t)hashlen);
	memset(hash, 0, (size_t)hashlen);
	ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashlen);
	OPENSSL_free(hash);

	*len  = i2d_SpcIndirectDataContent(idc, NULL);
	*blob = OPENSSL_malloc((size_t)*len);
	p = *blob;
	i2d_SpcIndirectDataContent(idc, &p);
	SpcIndirectDataContent_free(idc);
	*len -= EVP_MD_size(tdata->options->md);
	return 1; /* OK */
}

/*
 * Replace the data part with the MS Authenticode spcIndirectDataContent blob
 * [out] sig: PKCS#7 structure
 * [in] tdata: TYPE_DATA structure
 * [in] blob: SpcIndirectDataContent data
 * [in] len: SpcIndirectDataContent data length
 * [returns] 0 on error or 1 on success
 */
static int pkcs7_set_spc_indirect_data_content(PKCS7 *sig, TYPE_DATA *tdata, u_char *buf, int len)
{
	u_char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen, seqhdrlen;
	BIO *sigbio;
	PKCS7 *td7;

	mdlen = BIO_gets(tdata->sign->hash, (char*)mdbuf, EVP_MAX_MD_SIZE);
	memcpy(buf+len, mdbuf, (size_t)mdlen);
	seqhdrlen = asn1_simple_hdr_len(buf, len);

	if ((sigbio = PKCS7_dataInit(sig, NULL)) == NULL) {
		printf("PKCS7_dataInit failed\n");
		return 0; /* FAILED */
	}
	BIO_write(sigbio, buf+seqhdrlen, len-seqhdrlen+mdlen);
	(void)BIO_flush(sigbio);

	if (!PKCS7_dataFinal(sig, sigbio)) {
		printf("PKCS7_dataFinal failed\n");
		return 0; /* FAILED */
	}
	BIO_free_all(sigbio);

	td7 = PKCS7_new();
	td7->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	td7->d.other = ASN1_TYPE_new();
	td7->d.other->type = V_ASN1_SEQUENCE;
	td7->d.other->value.sequence = ASN1_STRING_new();
	ASN1_STRING_set(td7->d.other->value.sequence, buf, len+mdlen);
	if (!PKCS7_set_content(sig, td7)) {
		PKCS7_free(td7);
		printf("PKCS7_set_content failed\n");
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

static X509 *find_signer(PKCS7 *p7, char *leafhash, int *leafok)
{
	STACK_OF(X509) *signers;
	X509 *cert = NULL;
	int ret = 0;

	/*
	 * retrieve the signer's certificate from p7,
	 * search only internal certificates if it was requested
	 */
	signers = PKCS7_get0_signers(p7, NULL, 0);
	if (!signers || sk_X509_num(signers) != 1) {
		printf("PKCS7_get0_signers error\n");
		goto out;
	}
	printf("Signer's certificate:\n");
	cert = sk_X509_value(signers, 0);
	if ((cert == NULL) || (!print_cert(cert, 0)))
		goto out;
	if (leafhash != NULL && *leafok == 0)
		*leafok = verify_leaf_hash(cert, leafhash) == 0;

	ret = 1; /* OK */
out:
	if (!ret)
		ERR_print_errors_fp(stdout);
	sk_X509_free(signers);
	return cert;
}

static int print_certs(PKCS7 *p7)
{
	X509 *cert;
	int i, count;

	count = sk_X509_num(p7->d.sign->cert);
	printf("\nNumber of certificates: %d\n", count);
	for (i=0; i<count; i++) {
		cert = sk_X509_value(p7->d.sign->cert, i);
		if ((cert == NULL) || (!print_cert(cert, i)))
			return 0; /* FAILED */
	}
	return 1; /* OK */
}

static int print_cert(X509 *cert, int i)
{
	char *subject, *issuer, *serial;
	BIGNUM *serialbn;

	subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	serialbn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
	serial = BN_bn2hex(serialbn);
	if (i > 0)
		printf("\t------------------\n");
	printf("\tSigner #%d:\n\t\tSubject: %s\n\t\tIssuer : %s\n\t\tSerial : %s\n\t\tCertificate expiration date:\n",
			i, subject, issuer, serial);
	printf("\t\t\tnotBefore : ");
	asn1_print_time(X509_get0_notBefore(cert));
	printf("\t\t\tnotAfter : ");
	asn1_print_time(X509_get0_notAfter(cert));

	OPENSSL_free(subject);
	OPENSSL_free(issuer);
	BN_free(serialbn);
	OPENSSL_free(serial);
	return 1; /* OK */
}

static char *get_clrdp_url(X509 *cert)
{
	STACK_OF(DIST_POINT) *crldp;
	DIST_POINT *dp;
	GENERAL_NAMES *gens;
	GENERAL_NAME *gen;
	int i, j, gtype;
	ASN1_STRING *uri;
	char *url = NULL;

	crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
	if (!crldp)
		return NULL;

	for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
		dp = sk_DIST_POINT_value(crldp, i);
		if (!dp->distpoint || dp->distpoint->type != 0)
			continue;
		gens = dp->distpoint->name.fullname;
		for (j = 0; j < sk_GENERAL_NAME_num(gens); j++) {
			gen = sk_GENERAL_NAME_value(gens, j);
			uri = GENERAL_NAME_get0_value(gen, &gtype);
			if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
				url = OPENSSL_strdup((const char *)ASN1_STRING_get0_data(uri));
				if (strncmp(url, "http://", 7) == 0)
					goto out;
				OPENSSL_free(url);
				url = NULL;
			}
		}
	}
out:
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
	return url;
}

static int verify_timestamp(SIGNATURE *signature, TYPE_DATA *tdata)
{
	X509_STORE *store;
	STACK_OF(CMS_SignerInfo) *sinfos;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	CMS_SignerInfo *cmssi;
	X509 *signer;
	STACK_OF(X509_CRL) *crls;
	char *url;
	PKCS7_SIGNER_INFO *si;
	int verok = 0;

	store = X509_STORE_new();
	if (!store)
		goto out;
	if (load_file_lookup(store, tdata->options->tsa_cafile)) {
		/*
		 * The TSA signing key MUST be of a sufficient length to allow for a sufficiently
		 * long lifetime.  Even if this is done, the key will  have a finite lifetime.
		 * Thus, any token signed by the TSA SHOULD  be time-stamped again or notarized
		 * at a later date to renew the trust that exists in the TSA's signature.
		 * https://datatracker.ietf.org/doc/html/rfc3161#section-4
		 * Signtool does not respect this RFC and neither we do.
		 * So verify timestamp against the time of its creation.
		 */
		if (!set_store_time(store, signature->time)) {
			printf("Failed to set store time\n");
			X509_STORE_free(store);
			goto out;
		}
	} else {
		printf("Use the \"-TSA-CAfile\" option to add the Time-Stamp Authority certificates bundle to verify the Timestamp Server.\n");
		X509_STORE_free(store);
		goto out;
	}

	/* verify a CMS SignedData structure */
	if (!CMS_verify(signature->timestamp, NULL, store, 0, NULL, 0)) {
		printf("\nCMS_verify error\n");
		X509_STORE_free(store);
		goto out;
	}
	X509_STORE_free(store);

	sinfos = CMS_get0_SignerInfos(signature->timestamp);
	cmssi = sk_CMS_SignerInfo_value(sinfos, 0);
	CMS_SignerInfo_get0_algs(cmssi, NULL, &signer, NULL, NULL);

	url = get_clrdp_url(signer);
	if (url) {
		printf("TSA's CRL distribution point: %s\n", url);
		OPENSSL_free(url);
	}

	/* verify a Certificate Revocation List */
	crls = signature->p7->d.sign->crl;
	if (tdata->options->tsa_crlfile || crls) {
		STACK_OF(X509) *chain = CMS_get1_certs(signature->timestamp);
		int crlok = verify_crl(tdata->options->tsa_cafile, tdata->options->tsa_crlfile,
			crls, signer, chain);
		sk_X509_pop_free(chain, X509_free);
		printf("Timestamp Server Signature CRL verification: %s\n", crlok ? "ok" : "failed");
		if (!crlok)
			goto out;
	} else
		printf("\n");

	/* check extended key usage flag XKU_TIMESTAMP */
	if (!(X509_get_extended_key_usage(signer) & XKU_TIMESTAMP)) {
		printf("Unsupported Signer's certificate purpose XKU_TIMESTAMP\n");
		goto out;
	}

	/* verify the hash provided from the trusted timestamp */
	signer_info = PKCS7_get_signer_info(signature->p7);
	if (!signer_info)
		goto out;
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		goto out;
	if (!TST_verify(signature->timestamp, si))
		goto out;

	verok = 1; /* OK */
out:
	if (!verok)
		ERR_print_errors_fp(stdout);
	return verok;
}

static int verify_authenticode(SIGNATURE *signature, TYPE_DATA *tdata, X509 *signer)
{
	X509_STORE *store;
	STACK_OF(X509_CRL) *crls;
	BIO *bio = NULL;
	int verok = 0;

	store = X509_STORE_new();
	if (!store)
		goto out;
	if (!load_file_lookup(store, tdata->options->cafile)) {
		printf("Failed to add store lookup file\n");
		X509_STORE_free(store);
		goto out;
	}
	if (signature->time != INVALID_TIME) {
		printf("Signature verification time: ");
		print_time_t(signature->time);
		if (!set_store_time(store, signature->time)) {
			printf("Failed to set signature time\n");
			X509_STORE_free(store);
			goto out;
		}
	} else if (tdata->options->time != INVALID_TIME) {
		printf("Signature verification time: ");
		print_time_t(tdata->options->time);
		if (!set_store_time(store, tdata->options->time)) {
			printf("Failed to set verifying time\n");
			X509_STORE_free(store);
			goto out;
		}
	}
	/* verify a PKCS#7 signedData structure */
	if (signature->p7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE) {
		/* only verify the contents of the sequence */
		int seqhdrlen;
		seqhdrlen = asn1_simple_hdr_len(signature->p7->d.sign->contents->d.other->value.sequence->data,
			signature->p7->d.sign->contents->d.other->value.sequence->length);
		bio = BIO_new_mem_buf(signature->p7->d.sign->contents->d.other->value.sequence->data + seqhdrlen,
			signature->p7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);
	} else {
		/* verify the entire value */
		bio = BIO_new_mem_buf(signature->p7->d.sign->contents->d.other->value.sequence->data,
			signature->p7->d.sign->contents->d.other->value.sequence->length);
	}
	if (!PKCS7_verify(signature->p7, NULL, store, bio, NULL, 0)) {
		printf("\nPKCS7_verify error\n");
		X509_STORE_free(store);
		BIO_free(bio);
		goto out;
	}
	X509_STORE_free(store);
	BIO_free(bio);

	/* verify a Certificate Revocation List */
	crls = signature->p7->d.sign->crl;
	if (tdata->options->crlfile || crls) {
		STACK_OF(X509) *chain = signature->p7->d.sign->cert;
		int crlok = verify_crl(tdata->options->cafile, tdata->options->crlfile,
			crls, signer, chain);
		printf("Signature CRL verification: %s\n", crlok ? "ok" : "failed");
		if (!crlok)
			goto out;
	}

	/* check extended key usage flag XKU_CODE_SIGN */
	if (!(X509_get_extended_key_usage(signer) & XKU_CODE_SIGN)) {
		printf("Unsupported Signer's certificate purpose XKU_CODE_SIGN\n");
		goto out;
	}

	verok = 1; /* OK */
out:
	if (!verok)
		ERR_print_errors_fp(stdout);
	return verok;
}

/*
 * [out] signature:  SIGNATURE structure
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
 * [out] signature:  SIGNATURE structure
 * [in] unauth_attr: unsigned attributes list
 * [in] p7: PKCS#7 structure
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

/*
 * RFC3852: the message-digest authenticated attribute type MUST be
 * present when there are any authenticated attributes present
 */
static int print_attributes(SIGNATURE *signature, int verbose)
{
	const u_char *mdbuf;
	int len;

	if (!signature->digest)
		return 0; /* FAILED */

	printf("\nAuthenticated attributes:\n");
	printf("\tMessage digest algorithm: %s\n",
		(signature->md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2sn(signature->md_nid));
	mdbuf = ASN1_STRING_get0_data(signature->digest);
	len = ASN1_STRING_length(signature->digest);
	print_hash("\tMessage digest", "", mdbuf, len);
	printf("\tSigning time: ");
	print_time_t(signature->signtime);

	if (signature->purpose) {
		if (!memcmp(signature->purpose, purpose_comm, sizeof purpose_comm))
			printf("\tMicrosoft Commercial Code Signing purpose\n");
		else if (!memcmp(signature->purpose, purpose_ind, sizeof purpose_ind))
			printf("\tMicrosoft Individual Code Signing purpose\n");
		else
			printf("\tUnrecognized Code Signing purpose\n");
	}
	if (signature->url) {
		printf("\tURL description: %s\n", signature->url);
	}
	if (signature->desc) {
		printf("\tText description: %s\n", signature->desc);
	}
	if (signature->level) {
		if (!memcmp(signature->level, java_attrs_low, sizeof java_attrs_low))
			printf("\tLow level of permissions in Microsoft Internet Explorer 4.x for CAB files\n");
		else
			printf("\tUnrecognized level of permissions in Microsoft Internet Explorer 4.x for CAB files\n");
	}

	/* Unauthenticated attributes */
	if (signature->timestamp) {
		if (!cms_print_timestamp(signature->timestamp, signature->time))
			return 0; /* FAILED */
	}
	if (signature->blob) {
		if (verbose) {
			char *data_blob;
			data_blob = OPENSSL_buf2hexstr(signature->blob->data, signature->blob->length);
			printf("\nUnauthenticated Data Blob:\n%s\n", data_blob);
			OPENSSL_free(data_blob);
		}
		printf("\nUnauthenticated Data Blob length: %d bytes\n",signature->blob->length);
	}
	return 1; /* OK */
}

static int verify_leaf_hash(X509 *leaf, const char *leafhash)
{
	int ret = 1;
	u_char *mdbuf = NULL, *certbuf, *tmp;
	u_char cmdbuf[EVP_MAX_MD_SIZE];
	const EVP_MD *md;
	long mdlen = 0;
	size_t certlen, written;
	BIO *bhash = BIO_new(BIO_f_md());

	/* decode the provided hash */
	char *mdid = OPENSSL_strdup(leafhash);
	char *hash = strchr(mdid, ':');
	if (hash == NULL) {
		printf("\nUnable to parse -require-leaf-hash parameter: %s\n", leafhash);
		goto out;
	}
	*hash++ = '\0';
	md = EVP_get_digestbyname(mdid);
	if (md == NULL) {
		printf("\nUnable to lookup digest by name '%s'\n", mdid);
		goto out;
	}
	mdbuf = OPENSSL_hexstr2buf(hash, &mdlen);
	if (mdlen != EVP_MD_size(md)) {
		printf("\nHash length mismatch: '%s' digest must be %d bytes long (got %ld bytes)\n",
			mdid, EVP_MD_size(md), mdlen);
		goto out;
	}
	/* compute the leaf certificate hash */
	if (!BIO_set_md(bhash, md)) {
		printf("Unable to set the message digest of BIO\n");
		goto out;
	}
	BIO_push(bhash, BIO_new(BIO_s_null()));
	certlen = (size_t)i2d_X509(leaf, NULL);
	certbuf = OPENSSL_malloc(certlen);
	tmp = certbuf;
	i2d_X509(leaf, &tmp);
	if (!BIO_write_ex(bhash, certbuf, certlen, &written) || written != certlen) {
		OPENSSL_free(certbuf);
		goto out;
	}
	BIO_gets(bhash, (char*)cmdbuf, EVP_MD_size(md));
	OPENSSL_free(certbuf);

	/* compare the provided hash against the computed hash */
	if (memcmp(mdbuf, cmdbuf, (size_t)EVP_MD_size(md))) {
		print_hash("\nLeaf hash value mismatch", "computed", cmdbuf, EVP_MD_size(md));
		goto out;
	}
	ret = 0; /* OK */
out:
	BIO_free_all(bhash);
	OPENSSL_free(mdid);
	OPENSSL_free(mdbuf);
	return ret;
}

static int load_file_lookup(X509_STORE *store, char *certs)
{
	X509_LOOKUP *lookup;
	X509_VERIFY_PARAM *param;

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (!lookup || !certs)
		return 0; /* FAILED */
	if (!X509_load_cert_file(lookup, certs, X509_FILETYPE_PEM)) {
		printf("\nError: no certificate found\n");
		return 0; /* FAILED */
	}

	param = X509_STORE_get0_param(store);
	if (param == NULL)
		return 0; /* FAILED */
	if (!X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY))
		return 0; /* FAILED */
	if (!X509_STORE_set1_param(store, param))
		return 0; /* FAILED */

	return 1; /* OK */
}

static int set_store_time(X509_STORE *store, time_t time)
{
	X509_VERIFY_PARAM *param;

	param = X509_STORE_get0_param(store);
	if (param == NULL)
		return 0; /* FAILED */
	X509_VERIFY_PARAM_set_time(param, time);
	if (!X509_STORE_set1_param(store, param))
		return 0; /* FAILED */
	return 1; /* OK */
}

static int verify_crl(char *ca_file, char *crl_file, STACK_OF(X509_CRL) *crls,
	X509 *signer, STACK_OF(X509) *chain)
{
	X509_STORE *store = NULL;
	X509_STORE_CTX *ctx = NULL;
	int verok = 0;

	ctx = X509_STORE_CTX_new();
	if (!ctx)
		goto out;
	store = X509_STORE_new();
	if (!store)
		goto out;
	if (!load_crlfile_lookup(store, ca_file, crl_file))
		goto out;

	/* initialise an X509_STORE_CTX structure for subsequent use by X509_verify_cert()*/
	if (!X509_STORE_CTX_init(ctx, store, signer, chain))
		goto out;

	/* set an additional CRLs */
	if (crls)
		X509_STORE_CTX_set0_crls(ctx, crls);

	if (X509_verify_cert(ctx) <= 0) {
		int error = X509_STORE_CTX_get_error(ctx);
		printf("\nX509_verify_cert: certificate verify error: %s\n",
				X509_verify_cert_error_string(error));
		goto out;
	}
	verok = 1; /* OK */

out:
	if (!verok)
		ERR_print_errors_fp(stdout);
	/* NULL is a valid parameter value for X509_STORE_free() and X509_STORE_CTX_free() */
	X509_STORE_free(store);
	X509_STORE_CTX_free(ctx);
	return verok;
}

/*
 * compare the hash provided from the TSTInfo object against the hash computed
 * from the signature created by the signing certificate's private key
*/
static int TST_verify(CMS_ContentInfo *timestamp, PKCS7_SIGNER_INFO *si)
{
	ASN1_OCTET_STRING *hash, **pos;
	TimeStampToken *token = NULL;
	const u_char *p = NULL;
	u_char mdbuf[EVP_MAX_MD_SIZE];
	const EVP_MD *md;
	int md_nid;
	BIO *bhash;

	pos  = CMS_get0_content(timestamp);
	if (pos != NULL && *pos != NULL) {
		p = (*pos)->data;
		token = d2i_TimeStampToken(NULL, &p, (*pos)->length);
		if (token) {
			/* compute a hash from the encrypted message digest value of the file */
			md_nid = OBJ_obj2nid(token->messageImprint->digestAlgorithm->algorithm);
			md = EVP_get_digestbynid(md_nid);
			bhash = BIO_new(BIO_f_md());
			if (!BIO_set_md(bhash, md)) {
				printf("Unable to set the message digest of BIO\n");
				BIO_free_all(bhash);
				return 0;  /* FAILED */
			}
			BIO_push(bhash, BIO_new(BIO_s_null()));
			BIO_write(bhash, si->enc_digest->data, si->enc_digest->length);
			BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
			BIO_free_all(bhash);

			/* compare the provided hash against the computed hash */
			hash = token->messageImprint->digest;
			/* hash->length == EVP_MD_size(md) */
			if (memcmp(mdbuf, hash->data, (size_t)hash->length)) {
				printf("Hash value mismatch:\n\tMessage digest algorithm: %s\n",
						(md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_nid));
				print_hash("\tComputed message digest", "", mdbuf, EVP_MD_size(md));
				print_hash("\tReceived message digest", "", hash->data, hash->length);
				printf("\nFile's message digest verification: failed\n");
				TimeStampToken_free(token);
				return 0; /* FAILED */
			} /* else Computed and received message digests matched */
			TimeStampToken_free(token);
		} else
			/* our CMS_ContentInfo struct created for Authenticode Timestamp
			 * does not contain any TimeStampToken as specified in RFC 3161 */
			ERR_clear_error();
	}
	return 1; /* OK */
}


static int asn1_print_time(const ASN1_TIME *time)
{
	BIO *bp;

	if ((time == NULL) || (!ASN1_TIME_check(time))) {
		printf("N/A\n");
		return 0; /* FAILED */
	}
	bp = BIO_new_fp(stdout, BIO_NOCLOSE);
	ASN1_TIME_print(bp, time);
	BIO_free(bp);
	printf("\n");
	return 1; /* OK */
}

static int print_time_t(const time_t time)
{
	ASN1_TIME *s;
	int ret;

	if (time == INVALID_TIME) {
		printf("N/A\n");
		return 0; /* FAILED */
	}
	if ((s = ASN1_TIME_set(NULL, time)) == NULL) {
		printf("N/A\n");
		return 0; /* FAILED */
	}
	ret = asn1_print_time(s);
	ASN1_TIME_free(s);
	return ret;

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

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	int error = X509_STORE_CTX_get_error(ctx);
	int depth = X509_STORE_CTX_get_error_depth(ctx);

	if (!ok && error == X509_V_ERR_CERT_HAS_EXPIRED) {
		if (depth == 0) {
			printf("\nWarning: Ignoring expired signer certificate for CRL validation\n");
			return 1;
		} else {
			X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
			printf("\nError: Expired CA certificate:\n");
			print_cert(current_cert, 0);
			printf("\n");
		}
	}
	return ok;
}

static int load_crlfile_lookup(X509_STORE *store, char *certs, char *crl)
{
	X509_LOOKUP *lookup;
	X509_VERIFY_PARAM *param;

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (!lookup)
		return 0; /* FAILED */
	if (!X509_load_cert_file(lookup, certs, X509_FILETYPE_PEM)) {
		printf("\nError: no certificate found\n");
		return 0; /* FAILED */
	}
	if (crl && !X509_load_crl_file(lookup, crl, X509_FILETYPE_PEM)) {
		printf("\nError: no CRL found in %s\n", crl);
		return 0; /* FAILED */
	}

	param = X509_STORE_get0_param(store);
	if (param == NULL)
		return 0; /* FAILED */
	/* enable CRL checking for the certificate chain leaf certificate */
	if (!X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK))
		return 0; /* FAILED */
	if (!X509_STORE_set1_param(store, param))
		return 0; /* FAILED */
	X509_STORE_set_verify_cb(store, verify_callback);

	return 1; /* OK */
}

static int cms_print_timestamp(CMS_ContentInfo *cms, time_t time)
{
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *si;
	int md_nid;
	ASN1_INTEGER *serialno;
	char *issuer_name, *serial;
	BIGNUM *serialbn;
	X509_ALGOR *pdig;
	X509_NAME *issuer = NULL;

	sinfos = CMS_get0_SignerInfos(cms);
	if (sinfos == NULL)
		return 0; /* FAILED */
	si = sk_CMS_SignerInfo_value(sinfos, 0);
	if (si == NULL)
		return 0; /* FAILED */
	printf("\nThe signature is timestamped: ");
	print_time_t(time);
	CMS_SignerInfo_get0_algs(si, NULL, NULL, &pdig, NULL);
	if (pdig == NULL || pdig->algorithm == NULL)
		return 0; /* FAILED */
	md_nid = OBJ_obj2nid(pdig->algorithm);
	printf("Hash Algorithm: %s\n", (md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_nid));
	if (!CMS_SignerInfo_get0_signer_id(si, NULL, &issuer, &serialno) || !issuer)
		return 0; /* FAILED */
	issuer_name = X509_NAME_oneline(issuer, NULL, 0);
	serialbn = ASN1_INTEGER_to_BN(serialno, NULL);
	serial = BN_bn2hex(serialbn);
	printf("Timestamp Verified by:\n\t\tIssuer : %s\n\t\tSerial : %s\n", issuer_name, serial);
	OPENSSL_free(issuer_name);
	BN_free(serialbn);
	OPENSSL_free(serial);
	return 1; /* OK */
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
