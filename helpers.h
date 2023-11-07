/*
 * osslsigncode support library
 *
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */

/* Common functions */
uint32_t get_file_size(const char *infile);
char *map_file(const char *infile, const size_t size);
void unmap_file(char *indata, const size_t size);
int pkcs7_signer_info_add_signing_time(PKCS7_SIGNER_INFO *si, FILE_FORMAT_CTX *ctx);
PKCS7 *pkcs7_get_sigfile(FILE_FORMAT_CTX *ctx);
PKCS7 *pkcs7_create(FILE_FORMAT_CTX *ctx);
int add_indirect_data_object(PKCS7 *p7);
int sign_spc_indirect_data_content(PKCS7 *p7, BIO *hash, FILE_FORMAT_CTX *ctx);
int pkcs7_sign_content(PKCS7 *p7, u_char *data, int len);
int asn1_simple_hdr_len(const u_char *p, int len);
int bio_hash_data(BIO *hash, char *indata, size_t idx, size_t fileend);
void print_hash(const char *descript1, const char *descript2, const u_char *hashbuf, int length);
int is_content_type(PKCS7 *p7, const char *objid);
SpcLink *spc_link_obsolete_get(void);
PKCS7 *pkcs7_get(char *indata, uint32_t sigpos, uint32_t siglen);
int compare_digests(u_char *mdbuf, u_char *cmdbuf, int mdtype);

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: nil
End:

  vim: set ts=4 expandtab:
*/
