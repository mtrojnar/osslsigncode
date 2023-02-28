/*
 * osslsigncode support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */


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
static SpcSpOpusInfo *createOpus(const char *desc, const char *url);
static void tohex(const u_char *v, char *b, int len);
static file_type_t get_file_type(char *indata);
static int append_nested_signature(STACK_OF(X509_ATTRIBUTE) **unauth_attr, u_char *p, int len);
static int get_indirect_data_blob(TYPE_DATA *tdata, u_char **blob, int *len);
static int set_signing_blob(PKCS7 *sig, BIO *hash, u_char *buf, int len);
static X509 *find_signer(PKCS7 *p7, char *leafhash, int *leafok);
static int print_certs(PKCS7 *p7);
static int print_cert(X509 *cert, int i);
static char *get_clrdp_url(X509 *cert);
static int verify_timestamp(SIGNATURE *signature, TYPE_DATA *tdata);
static int verify_authenticode(SIGNATURE *signature, TYPE_DATA *tdata, X509 *signer);
static void get_signed_attributes(SIGNATURE *signature, STACK_OF(X509_ATTRIBUTE) *auth_attr);
static void get_unsigned_attributes(STACK_OF(SIGNATURE) **signatures, SIGNATURE *signature,
	STACK_OF(X509_ATTRIBUTE) *unauth_attr, PKCS7 *p7, int allownest);
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

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
