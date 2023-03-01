/*
 * osslsigncode support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */

/* Common functions */
uint32_t input_validation(GLOBAL_OPTIONS *options, file_type_t type);
uint32_t get_file_size(const char *infile);
char *map_file(const char *infile, const size_t size);
void unmap_file(char *indata, const size_t size);
int add_opus_attribute(PKCS7_SIGNER_INFO *si, char *desc, char *url);
int add_purpose_attribute(PKCS7_SIGNER_INFO *si, int comm);
int pkcs7_set_nested_signature(TYPE_DATA *tdata);
int pkcs7_add_signing_time(PKCS7_SIGNER_INFO *si, time_t time);
int asn1_simple_hdr_len(const u_char *p, int len);
int bio_hash_data(char *indata, BIO *hash, uint32_t idx, uint32_t offset, uint32_t fileend);
void print_hash(const char *descript1, const char *descript2, const u_char *hashbuf, int length);
int is_content_type(PKCS7 *p7, const char *objid);
int set_indirect_data_blob(TYPE_DATA *tdata, PKCS7 *sig);
int verify_signature(TYPE_DATA *tdata, SIGNATURE *signature);
int append_signature_list(STACK_OF(SIGNATURE) **signatures, PKCS7 *p7, int allownest);
void signature_free(SIGNATURE *signature);
SpcLink *get_obsolete_link(void);
int compare_digests(u_char *mdbuf, u_char *cmdbuf, int mdtype);

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
