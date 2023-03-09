/*
 * Copyright (C) 2021-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 */

#define OPENSSL_API_COMPAT 0x10100000L
#define OPENSSL_NO_DEPRECATED

#if defined(_MSC_VER) || defined(__MINGW32__)
#define HAVE_WINDOWS_H
#endif /* _MSC_VER || __MINGW32__ */

#ifdef HAVE_WINDOWS_H
#define NOCRYPT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif /* HAVE_WINDOWS_H */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif /* HAVE_SYS_MMAN_H */
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif /* HAVE_TERMIOS_H */
#endif /* _WIN32 */

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* OPENSSL_NO_ENGINE */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#if OPENSSL_VERSION_NUMBER>=0x30000000L
#include <openssl/provider.h>
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> /* X509_PURPOSE */

#ifdef ENABLE_CURL
#ifdef __CYGWIN__
#ifndef SOCKET
#define SOCKET UINT_PTR
#endif /* SOCKET */
#endif /* __CYGWIN__ */
#include <curl/curl.h>

#define MAX_TS_SERVERS 256
#endif /* ENABLE_CURL */

#if defined (HAVE_TERMIOS_H) || defined (HAVE_GETPASS)
#define PROVIDE_ASKPASS 1
#endif

#ifdef _WIN32
#define FILE_CREATE_MODE "w+b"
#else
#define FILE_CREATE_MODE "w+bx"
#endif


#define GET_UINT8_LE(p) ((const u_char *)(p))[0]

#define GET_UINT16_LE(p) (uint16_t)(((const u_char *)(p))[0] | \
                                   (((const u_char *)(p))[1] << 8))

#define GET_UINT32_LE(p) (uint32_t)(((const u_char *)(p))[0] | \
                                   (((const u_char *)(p))[1] << 8) | \
                                   (((const u_char *)(p))[2] << 16) | \
                                   (((const u_char *)(p))[3] << 24))

#define PUT_UINT8_LE(i, p) ((u_char *)(p))[0] = (u_char)((i) & 0xff);

#define PUT_UINT16_LE(i,p) ((u_char *)(p))[0] = (u_char)((i) & 0xff); \
                           ((u_char *)(p))[1] = (u_char)(((i) >> 8) & 0xff)

#define PUT_UINT32_LE(i,p) ((u_char *)(p))[0] = (u_char)((i) & 0xff); \
                           ((u_char *)(p))[1] = (u_char)(((i) >> 8) & 0xff); \
                           ((u_char *)(p))[2] = (u_char)(((i) >> 16) & 0xff); \
                           ((u_char *)(p))[3] = (u_char)(((i) >> 24) & 0xff)

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define SIZE_64K 65536       /* 2^16 */
#define SIZE_16M 16777216    /* 2^24 */

/*
 * Macro names:
 * linux:  __BYTE_ORDER == __LITTLE_ENDIAN | __BIG_ENDIAN
 *           BYTE_ORDER == LITTLE_ENDIAN | BIG_ENDIAN
 * bsd:     _BYTE_ORDER == _LITTLE_ENDIAN | _BIG_ENDIAN
 *           BYTE_ORDER == LITTLE_ENDIAN | BIG_ENDIAN
 * solaris: _LITTLE_ENDIAN | _BIG_ENDIAN
 */

#ifndef BYTE_ORDER
#define LITTLE_ENDIAN    1234
#define BIG_ENDIAN       4321
#define BYTE_ORDER       LITTLE_ENDIAN
#endif /* BYTE_ORDER */

#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
#error "Cannot determine the endian-ness of this platform"
#endif

#ifndef LOWORD
#define LOWORD(x) ((x) & 0xFFFF)
#endif /* LOWORD */
#ifndef HIWORD
#define HIWORD(x) (((x) >> 16) & 0xFFFF)
#endif /* HIWORD */

#if BYTE_ORDER == BIG_ENDIAN
#define LE_UINT16(x) ((((x) >> 8) & 0x00FF) | \
                     (((x) << 8) & 0xFF00))
#define LE_UINT32(x) (((x) >> 24) | \
                     (((x) & 0x00FF0000) >> 8) | \
                     (((x) & 0x0000FF00) << 8) | \
                     ((x) << 24))
#else
#define LE_UINT16(x) (x)
#define LE_UINT32(x) (x)
#endif /* BYTE_ORDER == BIG_ENDIAN */

#define MIN(a,b) ((a) < (b) ? a : b)
#define INVALID_TIME ((time_t)-1)

/* Microsoft OID Authenticode */
#define SPC_INDIRECT_DATA_OBJID      "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID     "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID       "1.3.6.1.4.1.311.2.1.12"
#define SPC_PE_IMAGE_DATA_OBJID      "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID           "1.3.6.1.4.1.311.2.1.25"
#define SPC_SIPINFO_OBJID            "1.3.6.1.4.1.311.2.1.30"
#define SPC_PE_IMAGE_PAGE_HASHES_V1  "1.3.6.1.4.1.311.2.3.1" /* SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2  "1.3.6.1.4.1.311.2.3.2" /* SHA256 */
#define SPC_NESTED_SIGNATURE_OBJID   "1.3.6.1.4.1.311.2.4.1"
/* Microsoft OID Time Stamping */
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_RFC3161_OBJID            "1.3.6.1.4.1.311.3.3.1"
/* Microsoft OID Crypto 2.0 */
#define MS_CTL_OBJID                 "1.3.6.1.4.1.311.10.1"
/* Microsoft OID Microsoft_Java */
#define MS_JAVA_SOMETHING            "1.3.6.1.4.1.311.15.1"

#define SPC_UNAUTHENTICATED_DATA_BLOB_OBJID  "1.3.6.1.4.1.42921.1.2.1"

/* Public Key Cryptography Standards PKCS#9 */
#define PKCS9_MESSAGE_DIGEST         "1.2.840.113549.1.9.4"
#define PKCS9_SIGNING_TIME           "1.2.840.113549.1.9.5"
#define PKCS9_COUNTER_SIGNATURE      "1.2.840.113549.1.9.6"

/* WIN_CERTIFICATE structure declared in Wintrust.h */
#define WIN_CERT_REVISION_2_0           0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002

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

#define DO_EXIT_0(x) { printf(x); goto err_cleanup; }
#define DO_EXIT_1(x, y) { printf(x, y); goto err_cleanup; }
#define DO_EXIT_2(x, y, z) { printf(x, y, z); goto err_cleanup; }

typedef enum {
	CMD_SIGN,
	CMD_EXTRACT,
	CMD_REMOVE,
	CMD_VERIFY,
	CMD_ADD,
	CMD_ATTACH,
	CMD_HELP,
	CMD_DEFAULT
} cmd_type_t;

typedef unsigned char u_char;

typedef struct SIGNATURE_st {
	PKCS7 *p7;
	int md_nid;
	ASN1_STRING *digest;
	time_t signtime;
	char *url;
	char *desc;
	const u_char *purpose;
	const u_char *level;
	CMS_ContentInfo *timestamp;
	time_t time;
	ASN1_STRING *blob;
} SIGNATURE;

DEFINE_STACK_OF(SIGNATURE)
DECLARE_ASN1_FUNCTIONS(SIGNATURE)

typedef struct {
	char *infile;
	char *outfile;
	char *sigfile;
	char *certfile;
	char *xcertfile;
	char *keyfile;
	char *pvkfile;
	char *pkcs12file;
	int output_pkcs7;
#ifndef OPENSSL_NO_ENGINE
	char *p11engine;
	char *p11module;
	char *p11cert;
#endif /* OPENSSL_NO_ENGINE */
	int askpass;
	char *readpass;
	char *pass;
	int comm;
	int pagehash;
	char *desc;
	const EVP_MD *md;
	char *url;
	time_t time;
#ifdef ENABLE_CURL
	char *turl[MAX_TS_SERVERS];
	int nturl;
	char *tsurl[MAX_TS_SERVERS];
	int ntsurl;
	char *proxy;
	int noverifypeer;
#endif /* ENABLE_CURL */
	int addBlob;
	int nest;
	int ignore_timestamp;
	int verbose;
	int add_msi_dse;
	char *catalog;
	char *cafile;
	char *crlfile;
	char *tsa_cafile;
	char *tsa_crlfile;
	char *leafhash;
	int jp;
#if OPENSSL_VERSION_NUMBER>=0x30000000L
	int legacy;
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *certs;
	STACK_OF(X509) *xcerts;
	STACK_OF(X509_CRL) *crls;
	cmd_type_t cmd;
	char *indata;
} GLOBAL_OPTIONS;

/*
 * ASN.1 definitions (more or less from official MS Authenticode docs)
 */
typedef struct {
	int type;
	union {
		ASN1_BMPSTRING *unicode;
		ASN1_IA5STRING *ascii;
	} value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

typedef struct {
	ASN1_OCTET_STRING *classId;
	ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

typedef struct {
	int type;
	union {
		ASN1_IA5STRING *url;
		SpcSerializedObject *moniker;
		SpcString *file;
	} value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

typedef struct {
	SpcString *programName;
	SpcLink   *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)

typedef struct {
	ASN1_OBJECT *type;
	ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

typedef struct {
	ASN1_OBJECT *algorithm;
	ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

typedef struct {
	SpcAttributeTypeAndOptionalValue *data;
	DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

typedef struct CatalogAuthAttr_st {
	ASN1_OBJECT *type;
	ASN1_TYPE *contents;
} CatalogAuthAttr;

DEFINE_STACK_OF(CatalogAuthAttr)
DECLARE_ASN1_FUNCTIONS(CatalogAuthAttr)

typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

#ifdef ENABLE_CURL

typedef struct {
	ASN1_OBJECT *type;
	ASN1_OCTET_STRING *signature;
} TimeStampRequestBlob;

DECLARE_ASN1_FUNCTIONS(TimeStampRequestBlob)

typedef struct {
	ASN1_OBJECT *type;
	TimeStampRequestBlob *blob;
} TimeStampRequest;

DECLARE_ASN1_FUNCTIONS(TimeStampRequest)

/* RFC3161 Time stamping */

typedef struct {
	ASN1_INTEGER *status;
	STACK_OF(ASN1_UTF8STRING) *statusString;
	ASN1_BIT_STRING *failInfo;
} PKIStatusInfo;

DECLARE_ASN1_FUNCTIONS(PKIStatusInfo)

typedef struct {
	PKIStatusInfo *status;
	PKCS7 *token;
} TimeStampResp;

DECLARE_ASN1_FUNCTIONS(TimeStampResp)

typedef struct {
	ASN1_INTEGER *version;
	MessageImprint *messageImprint;
	ASN1_OBJECT *reqPolicy;
	ASN1_INTEGER *nonce;
	ASN1_BOOLEAN certReq;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampReq;

DECLARE_ASN1_FUNCTIONS(TimeStampReq)

#endif /* ENABLE_CURL */

typedef struct {
	ASN1_INTEGER *seconds;
	ASN1_INTEGER *millis;
	ASN1_INTEGER *micros;
} TimeStampAccuracy;

DECLARE_ASN1_FUNCTIONS(TimeStampAccuracy)

typedef struct {
	ASN1_INTEGER *version;
	ASN1_OBJECT *policy_id;
	MessageImprint *messageImprint;
	ASN1_INTEGER *serial;
	ASN1_GENERALIZEDTIME *time;
	TimeStampAccuracy *accuracy;
	ASN1_BOOLEAN ordering;
	ASN1_INTEGER *nonce;
	GENERAL_NAME *tsa;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampToken;

DECLARE_ASN1_FUNCTIONS(TimeStampToken)

typedef struct file_format_st FILE_FORMAT;
typedef struct msi_ctx_st MSI_CTX;
typedef struct pe_ctx_st PE_CTX;
typedef struct cab_ctx_st CAB_CTX;
typedef struct cat_ctx_st CAT_CTX;

typedef struct {
	BIO *outdata;
	BIO *hash;
	PKCS7 *cursig; /* current signature */
	PKCS7 *sig;    /* new signature */
	int len;       /* signature length */
	int padlen;    /* signature padding length */
} SIGN_DATA;

typedef struct {
	FILE_FORMAT *format;
	GLOBAL_OPTIONS *options;
	SIGN_DATA *sign;
    union {
        MSI_CTX *msi_ctx;
        PE_CTX *pe_ctx;
        CAB_CTX *cab_ctx;
        CAT_CTX *cat_ctx;
    };
} FILE_FORMAT_CTX;

extern FILE_FORMAT file_format_msi;
extern FILE_FORMAT file_format_pe;
extern FILE_FORMAT file_format_cab;
extern FILE_FORMAT file_format_cat;

struct file_format_st {
	FILE_FORMAT_CTX *(*ctx_new) (GLOBAL_OPTIONS *option);
	ASN1_OBJECT *(*get_data_blob) (FILE_FORMAT_CTX *ctx, u_char **p, int *plen);
	STACK_OF(SIGNATURE) *(*signature_list_get) (FILE_FORMAT_CTX *ctx);
	int (*verify_digests) (FILE_FORMAT_CTX *ctx, SIGNATURE *signature);
	int (*extract_signature) (FILE_FORMAT_CTX *ctx);
	int (*remove_signature) (FILE_FORMAT_CTX *ctx);
	int (*prepare_signature) (FILE_FORMAT_CTX *ctx);
	int (*append_signature) (FILE_FORMAT_CTX *ctx);
	void (*update_data_size) (FILE_FORMAT_CTX *data);
	void (*ctx_free) (FILE_FORMAT_CTX *ctx);
	void (*ctx_cleanup) (FILE_FORMAT_CTX *ctx);
};

/*
Local Variables:
   c-basic-offset: 4
   tab-width: 4
   indent-tabs-mode: t
End:

  vim: set ts=4 noexpandtab:
*/
