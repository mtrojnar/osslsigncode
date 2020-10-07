/*
   OpenSSL based Authenticode signing for PE/MSI/Java CAB files.

   Copyright (C) 2005-2015 Per Allansson <pallansson@gmail.com>
   Copyright (C) 2018-2020 Michał Trojnara <Michal.Trojnara@stunnel.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   In addition, as a special exception, the copyright holders give
   permission to link the code of portions of this program with the
   OpenSSL library under certain conditions as described in each
   individual source file, and distribute linked combinations
   including the two.
   You must obey the GNU General Public License in all respects
   for all of the code used other than OpenSSL.  If you modify
   file(s) with this exception, you may extend this exception to your
   version of the file(s), but you are not obligated to do so.  If you
   do not wish to do so, delete this exception statement from your
   version.  If you delete this exception statement from all source
   files in the program, then also delete it here.
*/

/*
   Implemented with good help from:

   * Peter Gutmann's analysis of Authenticode:

	 https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt

   * MS CAB SDK documentation

	 https://docs.microsoft.com/en-us/previous-versions/ms974336(v=msdn.10)

   * MS PE/COFF documentation

	 https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

   * MS Windows Authenticode PE Signature Format

	 http://msdn.microsoft.com/en-US/windows/hardware/gg463183

	 (Although the part of how the actual checksumming is done is not
	 how it is done inside Windows. The end result is however the same
	 on all "normal" PE files.)

   * tail -c, tcpdump, mimencode & openssl asn1parse :)

*/

#define OPENSSL_API_COMPAT 0x10100000L
#define OPENSSL_NO_DEPRECATED

#ifdef __MINGW32__
#define HAVE_WINDOWS_H
#endif /* __MINGW32__ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_WINDOWS_H
#define NOCRYPT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef unsigned char u_char;
#endif /* HAVE_WINDOWS_H */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif /* _WIN32 */
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef _WIN32
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif /* HAVE_SYS_MMAN_H */

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif /* HAVE_TERMIOS_H */
#endif /* _WIN32 */

#ifdef WITH_GSF
#include <gsf/gsf-infile-msole.h>
#include <gsf/gsf-infile.h>
#include <gsf/gsf-input-stdio.h>
#include <gsf/gsf-outfile-msole.h>
#include <gsf/gsf-outfile.h>
#include <gsf/gsf-output-stdio.h>
#include <gsf/gsf-utils.h>
#endif /* WITH_GSF */

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> /* X509_PURPOSE */
#include <openssl/cms.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* OPENSSL_NO_ENGINE */

#ifdef ENABLE_CURL
#ifdef __CYGWIN__
#ifndef SOCKET
#define SOCKET UINT_PTR
#endif /* SOCKET */
#endif /* __CYGWIN__ */
#include <curl/curl.h>

#define MAX_TS_SERVERS 256
#endif /* ENABLE_CURL */

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define GSF_CAN_READ_MSI_METADATA

#if defined (HAVE_TERMIOS_H) || defined (HAVE_GETPASS)
#define PROVIDE_ASKPASS 1
#endif

#ifdef _WIN32
#define FILE_CREATE_MODE "w+b"
#else
#define FILE_CREATE_MODE "w+bx"
#endif

/* MS Authenticode object ids */
#define SPC_INDIRECT_DATA_OBJID      "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID     "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID       "1.3.6.1.4.1.311.2.1.12"
#define SPC_MS_JAVA_SOMETHING        "1.3.6.1.4.1.311.15.1"
#define SPC_PE_IMAGE_DATA_OBJID      "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID           "1.3.6.1.4.1.311.2.1.25"
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_SIPINFO_OBJID            "1.3.6.1.4.1.311.2.1.30"

#define SPC_PE_IMAGE_PAGE_HASHES_V1  "1.3.6.1.4.1.311.2.3.1" /* Page hash using SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2  "1.3.6.1.4.1.311.2.3.2" /* Page hash using SHA256 */

#define SPC_NESTED_SIGNATURE_OBJID   "1.3.6.1.4.1.311.2.4.1"

#define SPC_RFC3161_OBJID                        "1.3.6.1.4.1.311.3.3.1"
#define SPC_AUTHENTICODE_COUNTER_SIGNATURE_OBJID "1.2.840.113549.1.9.6"
#define SPC_UNAUTHENTICATED_DATA_BLOB_OBJID      "1.3.6.1.4.1.42921.1.2.1"
#define SPC_TIMESTAMP_SIGNING_TIME_OBJID         "1.2.840.113549.1.9.5"

/* 1.3.6.1.4.1.311.4... MS Crypto 2.0 stuff... */

#define WIN_CERT_REVISION_2             0x0200
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

#define INVALID_TIME ((time_t)-1)

typedef struct SIGNATURE_st {
	PKCS7 *p7;
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
	time_t signing_time;
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
	int timestamp_expiration;
	int verbose;
#ifdef WITH_GSF
	int add_msi_dse;
#endif /* WITH_GSF */
	char *cafile;
	char *crlfile;
	char *untrusted;
	char *crluntrusted;
	char *leafhash;
	int jp;
} GLOBAL_OPTIONS;

typedef struct {
	size_t header_size;
	int pe32plus;
	unsigned short magic;
	unsigned int pe_checksum;
	size_t nrvas;
	size_t sigpos;
	size_t siglen;
	size_t fileend;
	size_t flags;
} FILE_HEADER;

typedef struct {
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *certs;
	STACK_OF(X509) *xcerts;
	STACK_OF(X509_CRL) *crls;
} CRYPTO_PARAMS;

#ifdef WITH_GSF
typedef struct {
	GsfOutfile *outole;
	GsfOutput *sink;
	u_char *p_msiex;
	int len_msiex;
} GSF_PARAMS;
#endif /* WITH_GSF */


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

ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)


typedef struct {
	ASN1_OCTET_STRING *classId;
	ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)


typedef struct {
	int type;
	union {
		ASN1_IA5STRING *url;
		SpcSerializedObject *moniker;
		SpcString *file;
	} value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)


typedef struct {
	SpcString *programName;
	SpcLink   *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)


typedef struct {
	ASN1_OBJECT *type;
	ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)


typedef struct {
	ASN1_OBJECT *algorithm;
	ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)


typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)


typedef struct {
	SpcAttributeTypeAndOptionalValue *data;
	DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)


typedef struct {
	ASN1_BIT_STRING* flags;
	SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData)

ASN1_SEQUENCE(SpcPeImageData) = {
	ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
	ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)


typedef struct {
	ASN1_INTEGER *a;
	ASN1_OCTET_STRING *string;
	ASN1_INTEGER *b;
	ASN1_INTEGER *c;
	ASN1_INTEGER *d;
	ASN1_INTEGER *e;
	ASN1_INTEGER *f;
} SpcSipInfo;

DECLARE_ASN1_FUNCTIONS(SpcSipInfo)

ASN1_SEQUENCE(SpcSipInfo) = {
	ASN1_SIMPLE(SpcSipInfo, a, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, string, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSipInfo, b, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, c, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, d, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, e, ASN1_INTEGER),
	ASN1_SIMPLE(SpcSipInfo, f, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SpcSipInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSipInfo)


typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = {
	ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

#ifdef ENABLE_CURL

typedef struct {
	ASN1_OBJECT *type;
	ASN1_OCTET_STRING *signature;
} TimeStampRequestBlob;

DECLARE_ASN1_FUNCTIONS(TimeStampRequestBlob)

ASN1_SEQUENCE(TimeStampRequestBlob) = {
	ASN1_SIMPLE(TimeStampRequestBlob, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TimeStampRequestBlob, signature, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(TimeStampRequestBlob)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequestBlob)


typedef struct {
	ASN1_OBJECT *type;
	TimeStampRequestBlob *blob;
} TimeStampRequest;

DECLARE_ASN1_FUNCTIONS(TimeStampRequest)

ASN1_SEQUENCE(TimeStampRequest) = {
	ASN1_SIMPLE(TimeStampRequest, type, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampRequest, blob, TimeStampRequestBlob)
} ASN1_SEQUENCE_END(TimeStampRequest)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequest)

/* RFC3161 Time stamping */

typedef struct {
	ASN1_INTEGER *status;
	STACK_OF(ASN1_UTF8STRING) *statusString;
	ASN1_BIT_STRING *failInfo;
} PKIStatusInfo;

DECLARE_ASN1_FUNCTIONS(PKIStatusInfo)

ASN1_SEQUENCE(PKIStatusInfo) = {
	ASN1_SIMPLE(PKIStatusInfo, status, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(PKIStatusInfo, statusString, ASN1_UTF8STRING),
	ASN1_OPT(PKIStatusInfo, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PKIStatusInfo)

IMPLEMENT_ASN1_FUNCTIONS(PKIStatusInfo)


typedef struct {
	PKIStatusInfo *status;
	PKCS7 *token;
} TimeStampResp;

DECLARE_ASN1_FUNCTIONS(TimeStampResp)

ASN1_SEQUENCE(TimeStampResp) = {
	ASN1_SIMPLE(TimeStampResp, status, PKIStatusInfo),
	ASN1_OPT(TimeStampResp, token, PKCS7)
} ASN1_SEQUENCE_END(TimeStampResp)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampResp)


typedef struct {
	ASN1_INTEGER *version;
	MessageImprint *messageImprint;
	ASN1_OBJECT *reqPolicy;
	ASN1_INTEGER *nonce;
	ASN1_BOOLEAN *certReq;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampReq;

DECLARE_ASN1_FUNCTIONS(TimeStampReq)

ASN1_SEQUENCE(TimeStampReq) = {
	ASN1_SIMPLE(TimeStampReq, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, messageImprint, MessageImprint),
	ASN1_OPT   (TimeStampReq, reqPolicy, ASN1_OBJECT),
	ASN1_OPT   (TimeStampReq, nonce, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, certReq, ASN1_BOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampReq, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampReq)

#endif /* ENABLE_CURL */

typedef struct {
	ASN1_INTEGER *seconds;
	ASN1_INTEGER *millis;
	ASN1_INTEGER *micros;
} TimeStampAccuracy;

DECLARE_ASN1_FUNCTIONS(TimeStampAccuracy)

ASN1_SEQUENCE(TimeStampAccuracy) = {
	ASN1_OPT(TimeStampAccuracy, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(TimeStampAccuracy, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(TimeStampAccuracy, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TimeStampAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampAccuracy)


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

ASN1_SEQUENCE(TimeStampToken) = {
	ASN1_SIMPLE(TimeStampToken, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, policy_id, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampToken, messageImprint, MessageImprint),
	ASN1_SIMPLE(TimeStampToken, serial, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, time, ASN1_GENERALIZEDTIME),
	ASN1_OPT(TimeStampToken, accuracy, TimeStampAccuracy),
	ASN1_OPT(TimeStampToken, ordering, ASN1_FBOOLEAN),
	ASN1_OPT(TimeStampToken, nonce, ASN1_INTEGER),
	ASN1_EXP_OPT(TimeStampToken, tsa, GENERAL_NAME, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampToken, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TimeStampToken)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampToken)


static SpcSpOpusInfo *createOpus(const char *desc, const char *url)
{
	SpcSpOpusInfo *info = SpcSpOpusInfo_new();

	if (desc) {
		info->programName = SpcString_new();
		info->programName->type = 1;
		info->programName->value.ascii = ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->programName->value.ascii,
				(const unsigned char*)desc, strlen(desc));
	}
	if (url) {
		info->moreInfo = SpcLink_new();
		info->moreInfo->type = 0;
		info->moreInfo->value.url = ASN1_IA5STRING_new();
		ASN1_STRING_set((ASN1_STRING *)info->moreInfo->value.url,
				(const unsigned char*)url, strlen(url));
	}
	return info;
}

static size_t asn1_simple_hdr_len(const unsigned char *p, size_t len)
{
	if (len <= 2 || p[0] > 0x31)
		return 0;
	return (p[1]&0x80) ? (2 + (p[1]&0x7f)) : 2;
}

/*
 * Add a custom, non-trusted time to the PKCS7 structure to prevent OpenSSL
 * adding the _current_ time. This allows to create a deterministic signature
 * when no trusted timestamp server was specified, making osslsigncode
 * behaviour closer to signtool.exe (which doesn't include any non-trusted
 * time in this case.)
 */
static int pkcs7_add_signing_time(PKCS7_SIGNER_INFO *si, time_t signing_time)
{
	if (signing_time == INVALID_TIME) /* -st option was not specified */
		return 1; /* success */
	return PKCS7_add_signed_attribute(si,
		NID_pkcs9_signingTime, V_ASN1_UTCTIME,
		ASN1_TIME_adj(NULL, signing_time, 0, 0));
}

static void tohex(const unsigned char *v, char *b, int len)
{
	int i;
	for(i=0; i<len; i++)
		sprintf(b+i*2, "%02X", v[i]);
}

static int is_indirect_data_signature(PKCS7 *p7)
{
	ASN1_OBJECT *indir_objid;
	int retval;

	indir_objid = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
	retval = p7 && PKCS7_type_is_signed(p7) &&
		!OBJ_cmp(p7->d.sign->contents->type, indir_objid) &&
		p7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE;
	ASN1_OBJECT_free(indir_objid);
	return retval;
}

#ifdef ENABLE_CURL

static int blob_has_nl = 0;

/*
 * Callback for writing received data
 */
static size_t curl_write(void *ptr, size_t sz, size_t nmemb, void *stream)
{
	if (sz*nmemb > 0 && !blob_has_nl) {
		if (memchr(ptr, '\n', sz*nmemb))
			blob_has_nl = 1;
	}
	return BIO_write((BIO*)stream, ptr, sz*nmemb);
}

static void print_timestamp_error(const char *url, long http_code)
{
	if (http_code != -1) {
		printf("Failed to convert timestamp reply from %s; "
				"HTTP status %ld\n", url, http_code);
	} else {
		printf("Failed to convert timestamp reply from %s; "
				"no HTTP status available", url);
	}
	ERR_print_errors_fp(stdout);
}

/*
  A timestamp request looks like this:

  POST <someurl> HTTP/1.1
  Content-Type: application/octet-stream
  Content-Length: ...
  Accept: application/octet-stream
  User-Agent: Transport
  Host: ...
  Cache-Control: no-cache

  <base64encoded blob>

  .. and the blob has the following ASN1 structure:

  0:d=0  hl=4 l= 291 cons: SEQUENCE
  4:d=1  hl=2 l=  10 prim:  OBJECT         :1.3.6.1.4.1.311.3.2.1
  16:d=1 hl=4 l= 275 cons:  SEQUENCE
  20:d=2 hl=2 l=   9 prim:   OBJECT        :pkcs7-data
  31:d=2 hl=4 l= 260 cons:   cont [ 0 ]
  35:d=3 hl=4 l= 256 prim:    OCTET STRING
  <signature>

  .. and it returns a base64 encoded PKCS#7 structure.
*/

/*
 * Encode RFC 3161 timestamp request and write it into BIO
 */
static BIO *encode_rfc3161_request(PKCS7 *sig, const EVP_MD *md)
{
	PKCS7_SIGNER_INFO *si;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *mdctx;
	TimeStampReq *req;
	BIO *bout;
	u_char *p;
	int len;

	si = sk_PKCS7_SIGNER_INFO_value(sig->d.sign->signer_info, 0);
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit(mdctx, md);
	EVP_DigestUpdate(mdctx, si->enc_digest->data, si->enc_digest->length);
	EVP_DigestFinal(mdctx, mdbuf, NULL);
	EVP_MD_CTX_free(mdctx);

	req = TimeStampReq_new();
	ASN1_INTEGER_set(req->version, 1);
	req->messageImprint->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(md));
	req->messageImprint->digestAlgorithm->parameters = ASN1_TYPE_new();
	req->messageImprint->digestAlgorithm->parameters->type = V_ASN1_NULL;
	ASN1_OCTET_STRING_set(req->messageImprint->digest, mdbuf, EVP_MD_size(md));
	req->certReq = (void*)0x1;

	len = i2d_TimeStampReq(req, NULL);
	p = OPENSSL_malloc(len);
	len = i2d_TimeStampReq(req, &p);
	p -= len;
	TimeStampReq_free(req);

	bout = BIO_new(BIO_s_mem());
	BIO_write(bout, p, len);
	OPENSSL_free(p);
	(void)BIO_flush(bout);
	return bout;
}

/*
 * Encode authenticode timestamp request and write it into BIO
 */
static BIO *encode_authenticode_request(PKCS7 *sig)
{
	PKCS7_SIGNER_INFO *si;
	TimeStampRequest *req;
	BIO *bout, *b64;
	u_char *p;
	int len;

	req = TimeStampRequest_new();
	req->type = OBJ_txt2obj(SPC_TIME_STAMP_REQUEST_OBJID, 1);
	req->blob->type = OBJ_nid2obj(NID_pkcs7_data);
	si = sk_PKCS7_SIGNER_INFO_value(sig->d.sign->signer_info, 0);
	req->blob->signature = si->enc_digest;

	len = i2d_TimeStampRequest(req, NULL);
	p = OPENSSL_malloc(len);
	len = i2d_TimeStampRequest(req, &p);
	p -= len;
	req->blob->signature = NULL;
	TimeStampRequest_free(req);

	bout = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	bout = BIO_push(b64, bout);
	BIO_write(bout, p, len);
	OPENSSL_free(p);
	(void)BIO_flush(bout);
	return bout;
}

/*
 * Decode a curl response from BIO.
 * If successful the RFC 3161 timestamp will be written into
 * the PKCS7 SignerInfo structure as an unauthorized attribute - cont[1].
 */
static int decode_rfc3161_response(PKCS7 *sig, BIO *bin, int verbose)
{
	PKCS7_SIGNER_INFO *si;
	STACK_OF(X509_ATTRIBUTE) *attrs;
	TimeStampResp *reply;
	u_char *p;
	int len;

	reply = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TimeStampResp), bin, NULL);
	BIO_free_all(bin);
	if (!reply)
		return 1; /* FAILED */
	if (ASN1_INTEGER_get(reply->status->status) != 0) {
		if (verbose)
			printf("Timestamping failed: %ld\n", ASN1_INTEGER_get(reply->status->status));
		TimeStampResp_free(reply);
		return 1; /* FAILED */
	}
	if (((len = i2d_PKCS7(reply->token, NULL)) <= 0) || (p = OPENSSL_malloc(len)) == NULL) {
		if (verbose) {
			printf("Failed to convert pkcs7: %d\n", len);
			ERR_print_errors_fp(stdout);
		}
		TimeStampResp_free(reply);
		return 1; /* FAILED */
	}
	len = i2d_PKCS7(reply->token, &p);
	p -= len;
	TimeStampResp_free(reply);

	attrs = sk_X509_ATTRIBUTE_new_null();
	attrs = X509at_add1_attr_by_txt(&attrs, SPC_RFC3161_OBJID, V_ASN1_SET, p, len);
	OPENSSL_free(p);

	si = sk_PKCS7_SIGNER_INFO_value(sig->d.sign->signer_info, 0);
	PKCS7_set_attributes(si, attrs);
	sk_X509_ATTRIBUTE_pop_free(attrs, X509_ATTRIBUTE_free);
	return 0; /* OK */
}

/*
 * Decode a curl response from BIO.
 * If successful the authenticode timestamp will be written into
 * the PKCS7 SignerInfo structure as an unauthorized attribute - cont[1].
 */
static int decode_authenticode_response(PKCS7 *sig, BIO *bin, int verbose)
{
	PKCS7 *p7;
	PKCS7_SIGNER_INFO *info, *si;
	STACK_OF(X509_ATTRIBUTE) *attrs;
	BIO* b64, *b64_bin;
	u_char *p;
	int len, i;

	b64 = BIO_new(BIO_f_base64());
	if (!blob_has_nl)
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	b64_bin = BIO_push(b64, bin);
	p7 = d2i_PKCS7_bio(b64_bin, NULL);
	BIO_free_all(b64_bin);
	if (p7 == NULL)
		return 1; /* FAILED */

	for(i = sk_X509_num(p7->d.sign->cert)-1; i>=0; i--)
		PKCS7_add_certificate(sig, sk_X509_value(p7->d.sign->cert, i));

	info = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (((len = i2d_PKCS7_SIGNER_INFO(info, NULL)) <= 0) || (p = OPENSSL_malloc(len)) == NULL) {
		if (verbose) {
			printf("Failed to convert signer info: %d\n", len);
			ERR_print_errors_fp(stdout);
		}
		PKCS7_free(p7);
		return 1; /* FAILED */
	}
	len = i2d_PKCS7_SIGNER_INFO(info, &p);
	p -= len;
	PKCS7_free(p7);

	attrs = sk_X509_ATTRIBUTE_new_null();
	attrs = X509at_add1_attr_by_txt(&attrs, SPC_AUTHENTICODE_COUNTER_SIGNATURE_OBJID, V_ASN1_SET, p, len);
	OPENSSL_free(p);

	si = sk_PKCS7_SIGNER_INFO_value(sig->d.sign->signer_info, 0);
	/*
	 * PKCS7_set_attributes() frees up all elements of si->unauth_attr
	 * and sets there a copy of attrs so overrides the previous timestamp
	 */
	PKCS7_set_attributes(si, attrs);
	sk_X509_ATTRIBUTE_pop_free(attrs, X509_ATTRIBUTE_free);
	return 0; /* OK */
}

/*
 * Add timestamp to the PKCS7 SignerInfo structure:
 * sig->d.sign->signer_info->unauth_attr
 */
static int add_timestamp(PKCS7 *sig, char *url, char *proxy, int rfc3161,
	const EVP_MD *md, int verbose, int noverifypeer)
{
	CURL *curl;
	struct curl_slist *slist = NULL;
	CURLcode res;
	BIO *bout, *bin;
	u_char *p = NULL;
	int len = 0;

	if (!url)
		return 1; /* FAILED */
	/* Start a libcurl easy session and set options for a curl easy handle */
	curl = curl_easy_init();
	if (proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
		if (!strncmp("http:", proxy, 5))
			curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
		if (!strncmp("socks:", proxy, 6))
			curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	/*
	 * ask libcurl to show us the verbose output
	 * curl_easy_setopt(curl, CURLOPT_VERBOSE, 42);
	 */
	if (noverifypeer)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);

	if (rfc3161) {
		slist = curl_slist_append(slist, "Content-Type: application/timestamp-query");
		slist = curl_slist_append(slist, "Accept: application/timestamp-reply");
	} else {
		slist = curl_slist_append(slist, "Content-Type: application/octet-stream");
		slist = curl_slist_append(slist, "Accept: application/octet-stream");
	}
	slist = curl_slist_append(slist, "User-Agent: Transport");
	slist = curl_slist_append(slist, "Cache-Control: no-cache");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

	/* Encode timestamp request */
	if (rfc3161) {
		bout = encode_rfc3161_request(sig, md);
	} else {
		bout = encode_authenticode_request(sig);
	}
	len = BIO_get_mem_data(bout, &p);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)p);

	bin = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(bin, 0);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, bin);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
	/* Perform the request */
	res = curl_easy_perform(curl);
	curl_slist_free_all(slist);
	BIO_free_all(bout);

	if (res != CURLE_OK) {
		BIO_free_all(bin);
		if (verbose)
			printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	} else {
		/* CURLE_OK (0) */
		long http_code = -1;
		(void)BIO_flush(bin);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		/* Decode a curl response from BIO and write it into the PKCS7 structure */
		if (rfc3161)
			res = decode_rfc3161_response(sig, bin, verbose);
		else
			res = decode_authenticode_response(sig, bin, verbose);
		if (res && verbose)
			print_timestamp_error(url, http_code);
	}
	/* End a libcurl easy handle */
	curl_easy_cleanup(curl);
	return (int)res;
}

static int add_timestamp_authenticode(PKCS7 *sig, GLOBAL_OPTIONS *options)
{
	int i;
	for (i=0; i<options->nturl; i++) {
		int res = add_timestamp(sig, options->turl[i], options->proxy, 0, NULL,
				options->verbose || options->nturl == 1, options->noverifypeer);
		if (!res)
			return 0; /* OK */
	}
	return 1; /* FAILED */
}

static int add_timestamp_rfc3161(PKCS7 *sig, GLOBAL_OPTIONS *options)
{
	int i;
	for (i=0; i<options->ntsurl; i++) {
		int res = add_timestamp(sig, options->tsurl[i], options->proxy, 1, options->md,
				options->verbose || options->ntsurl == 1, options->noverifypeer);
		if (!res)
			return 0; /* OK */
	}
	return 1; /* FAILED */
}

#endif /* ENABLE_CURL */

#ifdef WITH_GSF
static int gsf_initialized = 0;
#endif /* WITH_GSF */

static bool on_list(const char *txt, const char *list[])
{
	while (*list)
		if (!strcmp(txt, *list++))
			return true;
	return false;
}

static void usage(const char *argv0, const char *cmd)
{
	const char *cmds_all[] = {"all", NULL};
	const char *cmds_sign[] = {"all", "sign", NULL};
	const char *cmds_add[] = {"all", "add", NULL};
	const char *cmds_attach[] = {"all", "attach-signature", NULL};
	const char *cmds_extract[] = {"all", "extract-signature", NULL};
	const char *cmds_remove[] = {"all", "remove-signature", NULL};
	const char *cmds_verify[] = {"all", "verify", NULL};

	printf("\nUsage: %s", argv0);
	if (on_list(cmd, cmds_all)) {
		printf("\n\n%1s[ --version | -v ]\n", "");
		printf("%1s[ --help ]\n\n", "");
	}
	if (on_list(cmd, cmds_sign)) {
		printf("%1s[ sign ] ( -certs <certfile> -key <keyfile> | -pkcs12 <pkcs12file> |\n", "");
		printf("%12s  [ -pkcs11engine <engine> ] -pkcs11module <module> -certs <certfile> -key <pkcs11 key id>)\n", "");
		printf("%12s[ -pass <password>", "");
#ifdef PROVIDE_ASKPASS
		printf("%1s [ -askpass ]", "");
#endif /* PROVIDE_ASKPASS */
		printf("%1s[ -readpass <file> ]\n", "");
		printf("%12s[ -ac <crosscertfile> ]\n", "");
		printf("%12s[ -h {md5,sha1,sha2(56),sha384,sha512} ]\n", "");
		printf("%12s[ -n <desc> ] [ -i <url> ] [ -jp <level> ] [ -comm ]\n", "");
		printf("%12s[ -ph ]\n", "");
#ifdef ENABLE_CURL
		printf("%12s[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer  ]\n", "");
		printf("%12s[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n", "");
#endif /* ENABLE_CURL */
		printf("%12s[ -st <unix-time> ]\n", "");
		printf("%12s[ -addUnauthenticatedBlob ]\n", "");
		printf("%12s[ -nest ]\n", "");
		printf("%12s[ -verbose ]\n", "");
#ifdef WITH_GSF
		printf("%12s[ -add-msi-dse ]\n", "");
#endif /* WITH_GSF */
		printf("%12s[ -in ] <infile> [-out ] <outfile>\n\n", "");
	}
	if (on_list(cmd, cmds_add)) {
		printf("%1sadd [-addUnauthenticatedBlob]\n", "");
#ifdef ENABLE_CURL
		printf("%12s[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer  ]\n", "");
		printf("%12s[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n", "");
#endif /* ENABLE_CURL */
		printf("%12s[ -verbose ]\n", "");
		printf("%12s[ -in ] <infile> [ -out ] <outfile>\n\n", "");
	}
	if (on_list(cmd, cmds_attach)) {
		printf("%1sattach-signature [ -sigin ] <sigfile>\n", "");
		printf("%12s[ -CAfile <infile> ]\n", "");
		printf("%12s[ -CRLfile <infile> ]\n", "");
		printf("%12s[ -untrusted <infile> ]\n", "");
		printf("%12s[ -CRLuntrusted <infile> ]\n", "");
		printf("%12s[ -nest ]\n", "");
		printf("%12s[ -in ] <infile> [ -out ] <outfile>\n\n", "");
	}
	if (on_list(cmd, cmds_extract)) {
		printf("%1sextract-signature [ -pem ]\n", "");
		printf("%12s[ -in ] <infile> [ -out ] <sigfile>\n\n", "");
	}
	if (on_list(cmd, cmds_remove))
		printf("%1sremove-signature [ -in ] <infile> [ -out ] <outfile>\n\n", "");
	if (on_list(cmd, cmds_verify)) {
		printf("%1sverify [ -in ] <infile>\n", "");
		printf("%12s[ -CAfile <infile> ]\n", "");
		printf("%12s[ -CRLfile <infile> ]\n", "");
		printf("%12s[ -untrusted <infile> ]\n", "");
		printf("%12s[ -CRLuntrusted <infile> ]\n", "");
		printf("%12s[ -require-leaf-hash {md5,sha1,sha2(56),sha384,sha512}:XXXXXXXXXXXX... ]\n", "");
		printf("%12s[ -timestamp-expiration ]\n", "");
		printf("%12s[ -verbose ]\n\n", "");
	}
	exit(-1);
}

static void help_for(const char *argv0, const char *cmd)
{
	const char *cmds_all[] = {"all", NULL};
	const char *cmds_add[] = {"add", NULL};
	const char *cmds_attach[] = {"attach-signature", NULL};
	const char *cmds_extract[] = {"extract-signature", NULL};
	const char *cmds_remove[] = {"remove-signature", NULL};
	const char *cmds_sign[] = {"sign", NULL};
	const char *cmds_verify[] = {"verify", NULL};
	const char *cmds_ac[] = {"sign", NULL};
#ifdef WITH_GSF
	const char *cmds_add_msi_dse[] = {"sign", NULL};
#endif /* WITH_GSF */
	const char *cmds_addUnauthenticatedBlob[] = {"sign", "add", NULL};
#ifdef PROVIDE_ASKPASS
	const char *cmds_askpass[] = {"sign", NULL};
#endif /* PROVIDE_ASKPASS */
	const char *cmds_CAfile[] = {"attach-signature", "verify", NULL};
	const char *cmds_certs[] = {"sign", NULL};
	const char *cmds_comm[] = {"sign", NULL};
	const char *cmds_CRLfile[] = {"attach-signature", "verify", NULL};
	const char *cmds_CRLuntrusted[] = {"attach-signature", "verify", NULL};
	const char *cmds_h[] = {"sign", NULL};
	const char *cmds_i[] = {"sign", NULL};
	const char *cmds_in[] = {"add", "attach-signature", "extract-signature", "remove-signature", "sign", "verify", NULL};
	const char *cmds_jp[] = {"sign", NULL};
	const char *cmds_key[] = {"sign", NULL};
	const char *cmds_n[] = {"sign", NULL};
	const char *cmds_nest[] = {"attach-signature", "sign", NULL};
#ifdef ENABLE_CURL
	const char *cmds_noverifypeer[] = {"add", "sign", NULL};
#endif /* ENABLE_CURL */
	const char *cmds_out[] = {"add", "attach-signature", "extract-signature", "remove-signature", "sign", NULL};
#ifdef ENABLE_CURL
	const char *cmds_p[] = {"add", "sign", NULL};
#endif /* ENABLE_CURL */
	const char *cmds_pass[] = {"sign", NULL};
	const char *cmds_pem[] = {"extract-signature", NULL};
	const char *cmds_ph[] = {"sign", NULL};
	const char *cmds_pkcs11cert[] = {"sign", NULL};
	const char *cmds_pkcs11engine[] = {"sign", NULL};
	const char *cmds_pkcs11module[] = {"sign", NULL};
	const char *cmds_pkcs12[] = {"sign", NULL};
	const char *cmds_readpass[] = {"sign", NULL};
	const char *cmds_require_leaf_hash[] = {"verify", NULL};
	const char *cmds_sigin[] = {"attach-signature", NULL};
	const char *cmds_st[] = {"sign", NULL};
	const char *cmds_timestamp_expiration[] = {"verify", NULL};
#ifdef ENABLE_CURL
	const char *cmds_t[] = {"add", "sign", NULL};
	const char *cmds_ts[] = {"add", "sign", NULL};
#endif /* ENABLE_CURL */
	const char *cmds_untrusted[] = {"attach-signature", "verify", NULL};
	const char *cmds_verbose[] = {"add", "sign", "verify", NULL};

	if (on_list(cmd, cmds_all)) {
		printf("osslsigncode is a small tool that implements part of the functionality of the Microsoft\n");
		printf("tool signtool.exe - more exactly the Authenticode signing and timestamping.\n");
		printf("It can sign and timestamp PE (EXE/SYS/DLL/etc), CAB and MSI files,\n");
		printf("supports getting the timestamp through a proxy as well.\n");
		printf("osslsigncode also supports signature verification, removal and extraction.\n\n");
		printf("%-22s = print osslsigncode version and usage\n", "--version | -v");
		printf("%-22s = print osslsigncode help menu\n\n", "--help");
		printf("Commands:\n");
		printf("%-22s = add an unauthenticated blob or a timestamp to a previously-signed file\n", "add");
		printf("%-22s = sign file using a given signature\n", "attach-signature");
		printf("%-22s = extract signature from a previously-signed file\n", "extract-signature");
		printf("%-22s = remove sections of the embedded signature on a file\n", "remove-signature");
		printf("%-22s = digitally sign a file\n", "sign");
		printf("%-22s = verifies the digital signature of a file\n\n", "verify");
		printf("For help on a specific command, enter %s <command> --help\n", argv0);
	}
	if (on_list(cmd, cmds_add)) {
		printf("\nUse the \"add\" command to add an unauthenticated blob or a timestamp to a previously-signed file.\n\n");
		printf("Options:\n");
	}
	if (on_list(cmd, cmds_attach)) {
		printf("\nUse the \"attach-signature\" command to attach the signature stored in the \"sigin\" file.\n");
		printf("In order to verify this signature you should specify how to find needed CA or TSA\n");
		printf("certificates, if appropriate.\n\n");
		printf("Options:\n");
	}
	if (on_list(cmd, cmds_extract)) {
		printf("\nUse the \"extract-signature\" command to extract the embedded signature from a previously-signed file.\n");
		printf("DER is the default format of the output file, but can be changed to PEM.\n\n");
		printf("Options:\n");
	}
	if (on_list(cmd, cmds_remove)) {
		printf("\nUse the \"remove-signature\" command to remove sections of the embedded signature on a file.\n\n");
		printf("Options:\n");
	}
	if (on_list(cmd, cmds_sign)) {
		printf("\nUse the \"sign\" command to sign files using embedded signatures.\n");
		printf("Signing  protects a file from tampering, and allows users to verify the signer\n");
		printf("based on a signing certificate. The options below allow you to specify signing\n");
		printf("parameters and to select the signing certificate you wish to use.\n\n");
		printf("Options:\n");
	}
	if (on_list(cmd, cmds_verify)) {
		printf("\nUse the \"verify\" command to verify embedded signatures.\n");
		printf("Verification determines if the signing certificate was issued by a trusted party,\n");
		printf("whether that certificate has been revoked, and whether the certificate is valid\n");
		printf("under a specific policy. Options allow you to specify requirements that must be met\n");
		printf("and to specify how to find needed CA or TSA certificates, if appropriate.\n\n");
		printf("Options:\n");
	}
	if (on_list(cmd, cmds_ac))
	printf("%-24s= additional certificates to be added to the signature block\n", "-ac");
#ifdef WITH_GSF
	if (on_list(cmd, cmds_add_msi_dse))
		printf("%-24s= sign a MSI file with the add-msi-dse option\n", "-add-msi-dse");
#endif /* WITH_GSF */
	if (on_list(cmd, cmds_addUnauthenticatedBlob))
		printf("%-24s= add an unauthenticated blob to the PE/MSI file\n", "-addUnauthenticatedBlob");
#ifdef PROVIDE_ASKPASS
	if (on_list(cmd, cmds_askpass))
		printf("%-24s= ask for the private key password\n", "-askpass");
#endif /* PROVIDE_ASKPASS */
	if (on_list(cmd, cmds_CAfile))
		printf("%-24s= the file containing one or more trusted certificates in PEM format\n", "-CAfile");
	if (on_list(cmd, cmds_certs))
		printf("%-24s= the signing certificate to use\n", "-certs");
	if (on_list(cmd, cmds_comm))
		printf("%-24s= set commercial purpose (default: individual purpose)\n", "-comm");
	if (on_list(cmd, cmds_CRLfile))
		printf("%-24s= the file containing one or more CRLs in PEM format\n", "-CRLfile");
	if (on_list(cmd, cmds_CRLuntrusted))
		printf("%-24s= the file containing one or more additional untrusted CRLs in PEM format\n", "-CRLuntrusted");
	if (on_list(cmd, cmds_h)) {
		printf("%-24s= {md5|sha1|sha2(56)|sha384|sha512}\n", "-h");
		printf("%26sset of cryptographic hash functions\n", "");
	}
	if (on_list(cmd, cmds_i))
		printf("%-24s= specifies a URL for expanded description of the signed content\n", "-i");
	if (on_list(cmd, cmds_in))
		printf("%-24s= input file\n", "-in");
	if (on_list(cmd, cmds_jp)) {
		printf("%-24s= low | medium | high\n", "-jp");
		printf("%26slevels of permissions in Microsoft Internet Explorer 4.x for CAB files\n", "");
		printf("%26sonly \"low\" level is now supported\n", "");
	}
	if (on_list(cmd, cmds_key))
		printf("%-24s= the private key to use or PKCS#11 URI identifies a key in the token\n", "-key");
	if (on_list(cmd, cmds_n))
		printf("%-24s= specifies a description of the signed content\n", "-n");
	if (on_list(cmd, cmds_nest))
		printf("%-24s= add the new nested signature instead of replacing the first one\n", "-nest");
#ifdef ENABLE_CURL
	if (on_list(cmd, cmds_noverifypeer))
		printf("%-24s= do not verify the Time-Stamp Authority's SSL certificate\n", "-noverifypeer");
#endif /* ENABLE_CURL */
	if (on_list(cmd, cmds_out))
		printf("%-24s= output file\n", "-out");
#ifdef ENABLE_CURL
	if (on_list(cmd, cmds_p))
		printf("%-24s= proxy to connect to the desired Time-Stamp Authority server\n", "-p");
#endif /* ENABLE_CURL */
	if (on_list(cmd, cmds_pass))
		printf("%-24s= the private key password\n", "-pass");
	if (on_list(cmd, cmds_pem))
		printf("%-24s= output data format PEM to use (default: DER)\n", "-pem");
	if (on_list(cmd, cmds_ph))
		printf("%-24s= generate page hashes for executable files\n", "-ph");
	if (on_list(cmd, cmds_pkcs11cert))
		printf("%-24s= PKCS#11 URI identifies a certificate in the token\n", "-pkcs11cert");
	if (on_list(cmd, cmds_pkcs11engine))
		printf("%-24s= PKCS11 engine\n", "-pkcs11engine");
	if (on_list(cmd, cmds_pkcs11module))
		printf("%-24s= PKCS11 module\n", "-pkcs11module");
	if (on_list(cmd, cmds_pkcs12))
		printf("%-24s= PKCS#12 container with the certificate and the private key\n", "-pkcs12");
	if (on_list(cmd, cmds_readpass))
		printf("%-24s= the private key password source\n", "-readpass");
	if (on_list(cmd, cmds_require_leaf_hash)) {
		printf("%-24s= {md5|sha1|sha2(56)|sha384|sha512}:XXXXXXXXXXXX...\n", "-require-leaf-hash");
		printf("%26sspecifies an optional hash algorithm to use when computing\n", "");
		printf("%26sthe leaf certificate (in DER form) hash and compares\n", "");
		printf("%26sthe provided hash against the computed hash\n", "");
	}
	if (on_list(cmd, cmds_sigin))
		printf("%-24s= a file containing the signature to be attached\n", "-sigin");
	if (on_list(cmd, cmds_st))
		printf("%-24s= the unix-time to set the signing time\n", "-st");
	if (on_list(cmd, cmds_timestamp_expiration))
		printf("%-24s= verify a finite lifetime of the TSA private key\n", "-st");
#ifdef ENABLE_CURL
	if (on_list(cmd, cmds_t)) {
		printf("%-24s= specifies that the digital signature will be timestamped\n", "-t");
		printf("%26sby the Time-Stamp Authority (TSA) indicated by the URL\n", "");
		printf("%26sthis option cannot be used with the -ts option\n", "");
	}
	if (on_list(cmd, cmds_ts)) {
		printf("%-24s= specifies the URL of the RFC 3161 Time-Stamp Authority server\n", "-ts");
		printf("%26sthis option cannot be used with the -t option\n", "");
	}
#endif /* ENABLE_CURL */
	if (on_list(cmd, cmds_untrusted)) {
		printf("%-24s= set of additional untrusted certificates which may be needed\n", "-untrusted");
		printf("%26sthe file should contain one or more certificates in PEM format\n", "");
	}
	if (on_list(cmd, cmds_verbose)) {
		printf("%-24s= include additional output in the log\n", "-verbose");
	}
	usage(argv0, cmd);
}

#define DO_EXIT_0(x) { printf(x); goto err_cleanup; }
#define DO_EXIT_1(x, y) { printf(x, y); goto err_cleanup; }
#define DO_EXIT_2(x, y, z) { printf(x, y, z); goto err_cleanup; }

#define GET_UINT8_LE(p) ((u_char*)(p))[0]

#define GET_UINT16_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8))

#define GET_UINT32_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8) | \
			(((u_char*)(p))[2]<<16) | (((u_char*)(p))[3]<<24))

#define PUT_UINT16_LE(i,p) \
	((u_char*)(p))[0] = (i) & 0xff; \
	((u_char*)(p))[1] = ((i)>>8) & 0xff

#define PUT_UINT32_LE(i,p) \
	((u_char*)(p))[0] = (i) & 0xff; \
	((u_char*)(p))[1] = ((i)>>8) & 0xff; \
	((u_char*)(p))[2] = ((i)>>16) & 0xff; \
	((u_char*)(p))[3] = ((i)>>24) & 0xff


typedef enum {
	FILE_TYPE_CAB,
	FILE_TYPE_PE,
	FILE_TYPE_MSI
} file_type_t;

typedef enum {
	CMD_SIGN,
	CMD_EXTRACT,
	CMD_REMOVE,
	CMD_VERIFY,
	CMD_ADD,
	CMD_ATTACH
} cmd_type_t;


static SpcLink *get_obsolete_link(void)
{
	static const unsigned char obsolete[] = {
		0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
		0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
		0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e
	};
	SpcLink *link = SpcLink_new();
	link->type = 2;
	link->value.file = SpcString_new();
	link->value.file->type = 0;
	link->value.file->value.unicode = ASN1_BMPSTRING_new();
	ASN1_STRING_set(link->value.file->value.unicode, obsolete, sizeof(obsolete));
	return link;
}

static const unsigned char classid_page_hash[] = {
	0xA6, 0xB5, 0x86, 0xD5, 0xB4, 0xA1, 0x24, 0x66,
	0xAE, 0x05, 0xA2, 0x17, 0xDA, 0x8E, 0x60, 0xD6
};

static unsigned char *pe_calc_page_hash(char *indata, size_t header_size,
	int pe32plus, size_t sigpos, int phtype, size_t *rphlen)
{
	unsigned short nsections, sizeofopthdr;
	size_t pagesize, hdrsize;
	size_t rs, ro, l, lastpos = 0;
	int pphlen, phlen, i, pi = 1;
	unsigned char *res, *zeroes;
	char *sections;
	const EVP_MD *md;
	EVP_MD_CTX *mdctx;

	nsections = GET_UINT16_LE(indata + header_size + 6);
	pagesize = GET_UINT32_LE(indata + header_size + 56);
	hdrsize = GET_UINT32_LE(indata + header_size + 84);
	md = EVP_get_digestbynid(phtype);
	pphlen = 4 + EVP_MD_size(md);
	phlen = pphlen * (3 + nsections + sigpos / pagesize);

	res = OPENSSL_malloc(phlen);
	zeroes = OPENSSL_zalloc(pagesize);

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit(mdctx, md);
	EVP_DigestUpdate(mdctx, indata, header_size + 88);
	EVP_DigestUpdate(mdctx, indata + header_size + 92, 60 + pe32plus*16);
	EVP_DigestUpdate(mdctx, indata + header_size + 160 + pe32plus*16,
			hdrsize - (header_size + 160 + pe32plus*16));
	EVP_DigestUpdate(mdctx, zeroes, pagesize - hdrsize);
	memset(res, 0, 4);
	EVP_DigestFinal(mdctx, res + 4, NULL);

	sizeofopthdr = GET_UINT16_LE(indata + header_size + 20);
	sections = indata + header_size + 24 + sizeofopthdr;
	for (i=0; i<nsections; i++) {
		rs = GET_UINT32_LE(sections + 16);
		ro = GET_UINT32_LE(sections + 20);
		for (l=0; l < rs; l+=pagesize, pi++) {
			PUT_UINT32_LE(ro + l, res + pi*pphlen);
			EVP_DigestInit(mdctx, md);
			if (rs - l < pagesize) {
				EVP_DigestUpdate(mdctx, indata + ro + l, rs - l);
				EVP_DigestUpdate(mdctx, zeroes, pagesize - (rs - l));
			} else {
				EVP_DigestUpdate(mdctx, indata + ro + l, pagesize);
			}
			EVP_DigestFinal(mdctx, res + pi*pphlen + 4, NULL);
		}
		lastpos = ro + rs;
		sections += 40;
	}
	EVP_MD_CTX_free(mdctx);
	PUT_UINT32_LE(lastpos, res + pi*pphlen);
	memset(res + pi*pphlen + 4, 0, EVP_MD_size(md));
	pi++;
	OPENSSL_free(zeroes);
	*rphlen = pi*pphlen;
	return res;
}

static SpcLink *get_page_hash_link(int phtype, char *indata, FILE_HEADER *header)
{
	unsigned char *ph, *p, *tmp;
	size_t l, phlen;
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	ASN1_TYPE *tostr;
	SpcAttributeTypeAndOptionalValue *aval;
	ASN1_TYPE *taval;
	SpcSerializedObject *so;
	SpcLink *link;
	STACK_OF(ASN1_TYPE) *oset, *aset;

	ph = pe_calc_page_hash(indata, header->header_size, header->pe32plus, \
			header->fileend, phtype, &phlen);
	if (!ph) {
		printf("Failed to calculate page hash\n");
		exit(-1);
	}
	tohex(ph, hexbuf, (phlen < 32) ? phlen : 32);
	printf("Calculated page hash            : %s ...\n", hexbuf);

	tostr = ASN1_TYPE_new();
	tostr->type = V_ASN1_OCTET_STRING;
	tostr->value.octet_string = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(tostr->value.octet_string, ph, phlen);
	OPENSSL_free(ph);

	oset = sk_ASN1_TYPE_new_null();
	sk_ASN1_TYPE_push(oset, tostr);
	l = i2d_ASN1_SET_ANY(oset, NULL);
	tmp = p = OPENSSL_malloc(l);
	i2d_ASN1_SET_ANY(oset, &tmp);
	ASN1_TYPE_free(tostr);
	sk_ASN1_TYPE_free(oset);

	aval = SpcAttributeTypeAndOptionalValue_new();
	aval->type = OBJ_txt2obj((phtype == NID_sha1) ? \
			SPC_PE_IMAGE_PAGE_HASHES_V1 : SPC_PE_IMAGE_PAGE_HASHES_V2, 1);
	aval->value = ASN1_TYPE_new();
	aval->value->type = V_ASN1_SET;
	aval->value->value.set = ASN1_STRING_new();
	ASN1_STRING_set(aval->value->value.set, p, l);
	OPENSSL_free(p);
	l = i2d_SpcAttributeTypeAndOptionalValue(aval, NULL);
	tmp = p = OPENSSL_malloc(l);
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
	tmp = p = OPENSSL_malloc(l);
	l = i2d_ASN1_SET_ANY(aset, &tmp);
	ASN1_TYPE_free(taval);
	sk_ASN1_TYPE_free(aset);

	so = SpcSerializedObject_new();
	ASN1_OCTET_STRING_set(so->classId, classid_page_hash, sizeof(classid_page_hash));
	ASN1_OCTET_STRING_set(so->serializedData, p, l);
	OPENSSL_free(p);

	link = SpcLink_new();
	link->type = 1;
	link->value.moniker = so;
	return link;
}

static void get_indirect_data_blob(u_char **blob, int *len, GLOBAL_OPTIONS *options,
			FILE_HEADER *header, file_type_t type, char *indata)
{
	u_char *p;
	int hashlen, l, phtype;
	void *hash;
	ASN1_OBJECT *dtype;
	SpcIndirectDataContent *idc;
	static const unsigned char msistr[] = {
		0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
	};

	idc = SpcIndirectDataContent_new();
	idc->data->value = ASN1_TYPE_new();
	idc->data->value->type = V_ASN1_SEQUENCE;
	idc->data->value->value.sequence = ASN1_STRING_new();
	if (type == FILE_TYPE_CAB) {
		SpcLink *link = get_obsolete_link();
		l = i2d_SpcLink(link, NULL);
		p = OPENSSL_malloc(l);
		i2d_SpcLink(link, &p);
		p -= l;
		dtype = OBJ_txt2obj(SPC_CAB_DATA_OBJID, 1);
		SpcLink_free(link);
	} else if (type == FILE_TYPE_PE) {
		SpcPeImageData *pid = SpcPeImageData_new();
		ASN1_BIT_STRING_set(pid->flags, (unsigned char*)"0", 0);
		if (options->pagehash) {
			phtype = NID_sha1;
			if (EVP_MD_size(options->md) > EVP_MD_size(EVP_sha1()))
				phtype = NID_sha256;
			pid->file = get_page_hash_link(phtype, indata, header);
		} else {
			pid->file = get_obsolete_link();
		}
		l = i2d_SpcPeImageData(pid, NULL);
		p = OPENSSL_malloc(l);
		i2d_SpcPeImageData(pid, &p);
		p -= l;
		dtype = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1);
		SpcPeImageData_free(pid);
	} else if (type == FILE_TYPE_MSI) {
		SpcSipInfo *si = SpcSipInfo_new();
		ASN1_INTEGER_set(si->a, 1);
		ASN1_INTEGER_set(si->b, 0);
		ASN1_INTEGER_set(si->c, 0);
		ASN1_INTEGER_set(si->d, 0);
		ASN1_INTEGER_set(si->e, 0);
		ASN1_INTEGER_set(si->f, 0);
		ASN1_OCTET_STRING_set(si->string, msistr, sizeof(msistr));
		l = i2d_SpcSipInfo(si, NULL);
		p = OPENSSL_malloc(l);
		i2d_SpcSipInfo(si, &p);
		p -= l;
		dtype = OBJ_txt2obj(SPC_SIPINFO_OBJID, 1);
		SpcSipInfo_free(si);
	} else {
		printf("Unexpected file type: %d\n", type);
		exit(1);
	}

	idc->data->type = dtype;
	idc->data->value->value.sequence->data = p;
	idc->data->value->value.sequence->length = l;
	idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(options->md));
	idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
	idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

	hashlen = EVP_MD_size(options->md);
	hash = OPENSSL_malloc(hashlen);
	memset(hash, 0, hashlen);
	ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashlen);
	OPENSSL_free(hash);

	*len  = i2d_SpcIndirectDataContent(idc, NULL);
	*blob = OPENSSL_malloc(*len);
	p = *blob;
	i2d_SpcIndirectDataContent(idc, &p);
	SpcIndirectDataContent_free(idc);
	*len -= EVP_MD_size(options->md);
}

static int set_signing_blob(PKCS7 *sig, BIO *hash, unsigned char *buf, int len)
{
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen;
	size_t seqhdrlen;
	BIO *sigbio;
	PKCS7 *td7;

	mdlen = BIO_gets(hash, (char*)mdbuf, EVP_MAX_MD_SIZE);
	memcpy(buf+len, mdbuf, mdlen);
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
	/*
	   replace the data part with the MS Authenticode
	   spcIndirectDataContext blob
	 */
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

static int set_indirect_data_blob(PKCS7 *sig, BIO *hash, file_type_t type,
				char *indata, GLOBAL_OPTIONS *options, FILE_HEADER *header)
{
	static unsigned char buf[64*1024];
	u_char *p = NULL;
	int len = 0;

	get_indirect_data_blob(&p, &len, options, header, type, indata);
	memcpy(buf, p, len);
	OPENSSL_free(p);
	if (!set_signing_blob(sig, hash, buf, len))
		return 0; /* FAILED */
	return 1; /* OK */
}

static unsigned int pe_calc_checksum(BIO *bio, FILE_HEADER *header)
{
	unsigned int checkSum = 0;
	unsigned short val;
	size_t size = 0;
	unsigned short *buf;
	int nread;

	/* recalculate the checksum */
	buf = OPENSSL_malloc(sizeof(unsigned short)*32768);
	(void)BIO_seek(bio, 0);
	while ((nread = BIO_read(bio, buf, sizeof(unsigned short)*32768)) > 0) {
		int i;
		for (i = 0; i < nread / 2; i++) {
			val = buf[i];
			if (size == header->header_size + 88 || size == header->header_size + 90)
				val = 0;
			checkSum += val;
			checkSum = 0xffff & (checkSum + (checkSum >> 0x10));
			size += 2;
		}
	}
	OPENSSL_free(buf);
	checkSum = 0xffff & (checkSum + (checkSum >> 0x10));
	checkSum += size;
	return checkSum;
}

static void pe_recalc_checksum(BIO *bio, FILE_HEADER *header)
{
	unsigned int checkSum = pe_calc_checksum(bio, header);
	char buf[4];

	/* write back checksum */
	(void)BIO_seek(bio, header->header_size + 88);
	PUT_UINT32_LE(checkSum, buf);
	BIO_write(bio, buf, 4);
}

static int verify_leaf_hash(X509 *leaf, const char *leafhash)
{
	int ret = 1;
	unsigned char *mdbuf = NULL, *certbuf, *tmp;
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	const EVP_MD *md;
	long mdlen = 0;
	EVP_MD_CTX *ctx;
	size_t certlen;

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
	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	certlen = i2d_X509(leaf, NULL);
	certbuf = OPENSSL_malloc(certlen);
	tmp = certbuf;
	i2d_X509(leaf, &tmp);
	EVP_DigestUpdate(ctx, certbuf, certlen);
	OPENSSL_free(certbuf);
	EVP_DigestFinal_ex(ctx, cmdbuf, NULL);
	EVP_MD_CTX_destroy(ctx);

	/* compare the provided hash against the computed hash */
	if (memcmp(mdbuf, cmdbuf, EVP_MD_size(md))) {
		tohex(cmdbuf, hexbuf, EVP_MD_size(md));
		printf("\nHash value mismatch: %s computed\n", hexbuf);
		goto out;
	}

	ret = 0; /* OK */
out:
	OPENSSL_free(mdid);
	OPENSSL_free(mdbuf);
	return ret;
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

static time_t asn1_get_time_t(ASN1_TIME *s)
{
	struct tm tm;

	if (ASN1_TIME_to_tm(s, &tm)) {
		return mktime(&tm);
	} else {
		return INVALID_TIME;
	}
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
			OBJ_obj2txt(object_txt, sizeof(object_txt), object, 1);
			if (!strcmp(object_txt, SPC_TIMESTAMP_SIGNING_TIME_OBJID)) {
				/* "1.2.840.113549.1.9.5" */
				time = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
			}
		}
	posix_time = asn1_get_time_t(time);
	return posix_time;
}

static time_t cms_get_time(CMS_ContentInfo *cms)
{
	ASN1_OCTET_STRING **pos;
	const unsigned char *p = NULL;
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
			printf("\nErrror: Expired CA certificate:\n");
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

static int load_file_lookup(X509_STORE *store, char *certs)
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

static int cms_print_timestamp(CMS_ContentInfo *cms, time_t time)
{
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *si;
	int md_nid;
	ASN1_INTEGER *serialno;
	char *issuer_name, *serial;
	BIGNUM *serialbn;
	X509_ALGOR *pdig;
	X509_NAME *issuer;

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
	if (!CMS_SignerInfo_get0_signer_id(si, NULL, &issuer, &serialno))
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
static CMS_ContentInfo *cms_get_timestamp(PKCS7_SIGNED *p7_signed, PKCS7_SIGNER_INFO *countersignature)
{
	CMS_ContentInfo *cms = NULL;
	PKCS7_SIGNER_INFO *si;
	PKCS7 *p7 = NULL, *content = NULL;
	unsigned char *p = NULL;
	const unsigned char *q;
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
	if (((len = i2d_PKCS7(p7, NULL)) <= 0) || (p = OPENSSL_malloc(len)) == NULL) {
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

static int print_attributes(SIGNATURE *signature, int verbose)
{
	if (signature->timestamp)
		if (!cms_print_timestamp(signature->timestamp, signature->time))
			return 0; /* FAILED */
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

static int append_signature_list(STACK_OF(SIGNATURE) **signatures, PKCS7 *p7, int allownest)
{
	SIGNATURE *signature = NULL;
	PKCS7_SIGNER_INFO *si, *countersi;
	STACK_OF(X509_ATTRIBUTE) *unauth_attr;
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	char object_txt[128];
	const unsigned char *data;
	int i, j;

	si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (si == NULL)
		return 0; /* FAILED */

	signature = OPENSSL_malloc(sizeof(SIGNATURE));
	signature->p7 = p7;
	signature->timestamp = NULL;
	signature->time = INVALID_TIME;
	signature->blob = NULL;

	unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
	if (unauth_attr)
		for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
			attr = X509at_get_attr(unauth_attr, i);
			object = X509_ATTRIBUTE_get0_object(attr);
			if (object == NULL)
				continue;
			object_txt[0] = 0x00;
			OBJ_obj2txt(object_txt, sizeof(object_txt), object, 1);
			if (!strcmp(object_txt, SPC_AUTHENTICODE_COUNTER_SIGNATURE_OBJID)) {
				/* Authenticode Timestamp - Policy OID: 1.2.840.113549.1.9.6 */
				CMS_ContentInfo *timestamp = NULL;
				time_t time;
				value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
				if (value == NULL)
					continue;
				data = value->data;
				countersi = d2i_PKCS7_SIGNER_INFO(NULL, &data, value->length);
				if (countersi == NULL)
					continue;
				time = si_get_time(countersi);
				if (time != INVALID_TIME) {
					timestamp = cms_get_timestamp(p7->d.sign, countersi);
					if (timestamp) {
						signature->time = time;
						signature->timestamp = timestamp;
					} else {
						printf("Error: Authenticode Timestamp could not be decoded correctly\n\n");
						PKCS7_SIGNER_INFO_free(countersi);
					}
				} else {
					printf("Error: SPC_TIMESTAMP_SIGNING_TIME_OBJID attribute not found\n\n");
					PKCS7_SIGNER_INFO_free(countersi);
				}
			} else if (!strcmp(object_txt, SPC_RFC3161_OBJID)) {
				/* RFC3161 Timestamp - Policy OID: 1.3.6.1.4.1.311.3.3.1 */
				CMS_ContentInfo *timestamp = NULL;
				time_t time;
				value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
				if (value == NULL)
					continue;
				data = value->data;
				timestamp = d2i_CMS_ContentInfo(NULL, &data, value->length);
				if (timestamp) {
					time = cms_get_time(timestamp);
					if (time != INVALID_TIME) {
						signature->time = time;
						signature->timestamp = timestamp;
					} else {
						printf("Error: Corrupt RFC3161 Timestamp embedded content\n\n");
						ERR_print_errors_fp(stdout);
					}
				} else {
					printf("Error: RFC3161 Timestamp could not be decoded correctly\n\n");
					ERR_print_errors_fp(stdout);
				}
			} else if (allownest && !strcmp(object_txt, SPC_NESTED_SIGNATURE_OBJID)) {
				/* Nested Signature - Policy OID: 1.3.6.1.4.1.311.2.4.1 */
				PKCS7 *nested;
				for (j=0; j<X509_ATTRIBUTE_count(attr); j++) {
					value = X509_ATTRIBUTE_get0_data(attr, j, V_ASN1_SEQUENCE, NULL);
					if (value == NULL)
						continue;
					data = value->data;
					nested = d2i_PKCS7(NULL, &data, value->length);
					if (nested)
						(void)append_signature_list(signatures, nested, 0);
				}
			} else if (!strcmp(object_txt, SPC_UNAUTHENTICATED_DATA_BLOB_OBJID)) {
				/* Unauthenticated Data Blob - Policy OID: 1.3.6.1.4.1.42921.1.2.1 */
				signature->blob = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTF8STRING, NULL);
			} else
				printf("Unsupported Policy OID: %s\n\n", object_txt);
		}

	if (!sk_SIGNATURE_unshift(*signatures, signature)) {
		if (signature->timestamp) {
			CMS_ContentInfo_free(signature->timestamp);
			ERR_clear_error();
		}
		PKCS7_free(signature->p7);
		OPENSSL_free(signature);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

/*
 * compare the hash provided from the TSTInfo object against the hash computed
 * from the signature created by the signing certificate's private key
*/
static int TST_verify(CMS_ContentInfo *timestamp, PKCS7_SIGNER_INFO *si)
{
	ASN1_OCTET_STRING *hash, **pos;
	TimeStampToken *token = NULL;
	const unsigned char *p = NULL;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
	int md_nid;

	pos  = CMS_get0_content(timestamp);
	if (pos != NULL && *pos != NULL) {
		p = (*pos)->data;
		token = d2i_TimeStampToken(NULL, &p, (*pos)->length);
		if (token) {
			/* compute a hash from the encrypted message digest value of the file */
			md_nid = OBJ_obj2nid(token->messageImprint->digestAlgorithm->algorithm);
			md = EVP_get_digestbynid(md_nid);
			mdctx = EVP_MD_CTX_new();
			EVP_DigestInit(mdctx, md);
			EVP_DigestUpdate(mdctx, si->enc_digest->data, si->enc_digest->length);
			EVP_DigestFinal(mdctx, mdbuf, NULL);
			EVP_MD_CTX_free(mdctx);

			/* compare the provided hash against the computed hash */
			hash = token->messageImprint->digest;
			/* hash->length == EVP_MD_size(md) */
			if (memcmp(mdbuf, hash->data, hash->length)) {
				tohex(mdbuf, hexbuf, EVP_MD_size(md));
				printf("Hash value mismatch:\n\tMessage digest algorithm: %s\n",
						(md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_nid));
				printf("\tComputed message digest : %s\n", hexbuf);
				tohex(hash->data, hexbuf, hash->length);
				printf("\tReceived message digest : %s\n" , hexbuf);
				printf("File's message digest verification: failed\n");
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

static int append_nested_signature(STACK_OF(X509_ATTRIBUTE) **unauth_attr, u_char *p, int len)
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
	if (!(attr = X509_ATTRIBUTE_create_by_NID(NULL, nid, V_ASN1_SEQUENCE, p, len)))
		return 0; /* FAILED */
	if (!sk_X509_ATTRIBUTE_push(*unauth_attr, attr)) {
		X509_ATTRIBUTE_free(attr);
		return 0; /* FAILED */
	}

	return 1; /* OK */
}

/*
 * pkcs7_set_nested_signature adds the p7nest signature to p7
 * as a nested signature (SPC_NESTED_SIGNATURE).
 */
static int pkcs7_set_nested_signature(PKCS7 *p7, PKCS7 *p7nest, time_t signing_time)
{
	u_char *p = NULL;
	int len = 0;
	PKCS7_SIGNER_INFO *si;

	if (((len = i2d_PKCS7(p7nest, NULL)) <= 0) ||
		(p = OPENSSL_malloc(len)) == NULL)
		return 0;
	i2d_PKCS7(p7nest, &p);
	p -= len;

	si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	pkcs7_add_signing_time(si, signing_time);
	if (!append_nested_signature(&(si->unauth_attr), p, len)) {
		OPENSSL_free(p);
		return 0;
	}
	OPENSSL_free(p);
	return 1;
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
			}
		}
	}
out:
	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
	return url;
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

static int verify_timestamp(SIGNATURE *signature, GLOBAL_OPTIONS *options)
{
	X509_STORE *store;
	STACK_OF(CMS_SignerInfo) *sinfos;
	CMS_SignerInfo *cmssi;
	X509 *signer;
	STACK_OF(X509_CRL) *crls;
	char *url;
	PKCS7_SIGNER_INFO *si;
	int verok = 0;

	store = X509_STORE_new();
	if (!store)
		goto out;
	if (load_file_lookup(store, options->untrusted)) {
		/*
		 * The TSA signing key MUST be of a sufficient length to allow for a sufficiently
		 * long lifetime.  Even if this is done, the key will  have a finite lifetime.
		 * Thus, any token signed by the TSA SHOULD  be time-stamped again or notarized
		 * at a later date to renew the trust that exists in the TSA's signature.
		 * https://tools.ietf.org/html/rfc3161
		*/
		if (!options->timestamp_expiration)
			/* verify timestamp against the time of its creation */
			if (!set_store_time(store, signature->time)) {
				printf("Failed to set store time\n");
				X509_STORE_free(store);
				goto out;
			}
	} else {
		printf("Use the \"-untrusted\" option to add the CA cert bundle to verify timestamp server.\n");
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
	printf("\n");

	/* verify a Certificate Revocation List */
	crls = signature->p7->d.sign->crl;
	if (options->crluntrusted || crls) {
		STACK_OF(X509) *chain = CMS_get1_certs(signature->timestamp);
		int crlok = verify_crl(options->untrusted, options->crluntrusted, crls, signer, chain);
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
	si = sk_PKCS7_SIGNER_INFO_value(signature->p7->d.sign->signer_info, 0);
	if (!TST_verify(signature->timestamp, si))
		goto out;

	verok = 1; /* OK */
out:
	if (!verok)
		ERR_print_errors_fp(stdout);
	return verok;
}

static int verify_authenticode(SIGNATURE *signature, GLOBAL_OPTIONS *options, X509 *signer)
{
	X509_STORE *store;
	STACK_OF(X509_CRL) *crls;
	size_t seqhdrlen;
	BIO *bio = NULL;
	int verok = 0;

	store = X509_STORE_new();
	if (!store)
		goto out;
	if (!load_file_lookup(store, options->cafile)) {
		printf("Failed to add store lookup file\n");
		X509_STORE_free(store);
		goto out;
	}
	if (signature->time != INVALID_TIME && !set_store_time(store, signature->time)) {
		printf("Failed to set store time\n");
		X509_STORE_free(store);
		goto out;
	}

	/* verify a PKCS#7 signedData structure */
	seqhdrlen = asn1_simple_hdr_len(signature->p7->d.sign->contents->d.other->value.sequence->data,
		signature->p7->d.sign->contents->d.other->value.sequence->length);
	bio = BIO_new_mem_buf(signature->p7->d.sign->contents->d.other->value.sequence->data + seqhdrlen,
		signature->p7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);
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
	if (options->crlfile || crls) {
		STACK_OF(X509) *chain = signature->p7->d.sign->cert;
		int crlok = verify_crl(options->cafile, options->crlfile, crls, signer, chain);
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

static int verify_signature(SIGNATURE *signature, GLOBAL_OPTIONS *options)
{
	int leafok = 0, verok;
	X509 *signer;
	char *url;

	signer = find_signer(signature->p7, options->leafhash, &leafok);
	if (!signer) {
		printf("Find signer error\n");
		return 1; /* FAILED */
	}
	if (!print_certs(signature->p7))
		printf("Print certs error\n");
	if (!print_attributes(signature, options->verbose))
		printf("Print attributes error\n");
	if (options->leafhash != NULL) {
		printf("\nLeaf hash match: %s\n", leafok ? "ok" : "failed");
		if (!leafok) {
			printf("Signature verification: failed\n\n");
			return 1; /* FAILED */
		}
	}
	printf("\nCAfile: %s\n", options->cafile);
	if (options->crlfile)
		printf("CRLfile: %s\n", options->crlfile);
	if (options->untrusted)
		printf("TSA's certificates file: %s\n", options->untrusted);
	if (options->crluntrusted)
		printf("TSA's CRL file: %s\n", options->crluntrusted);
	url = get_clrdp_url(signer);
	if (url) {
		printf("CRL distribution point: %s\n", url);
		OPENSSL_free(url);
	}

	if (signature->timestamp) {
		int timeok = verify_timestamp(signature, options);
		printf("Timestamp Server Signature verification: %s\n", timeok ? "ok" : "failed");
		if (!timeok) {
			signature->time = INVALID_TIME;
		}
	} else
		printf("\nTimestamp is not available\n\n");
	verok = verify_authenticode(signature, options, signer);
	printf("Signature verification: %s\n\n", verok ? "ok" : "failed");
	if (!verok)
		return 1; /* FAILED */

	return 0; /* OK */
}

#ifdef WITH_GSF
/*
 * MSI file support
 */
static gint msi_base64_decode(gint x)
{
	if (x < 10)
		return x + '0';
	if (x < (10 + 26))
		return x - 10 + 'A';
	if (x < (10 + 26 + 26))
		return x - 10 - 26 + 'a';
	if (x == (10 + 26 + 26))
		return '.';
	return 1;
}

static void msi_decode(const guint8 *in, gchar *out)
{
	guint count = 0;
	guint8 *q = (guint8 *)out;

	/* utf-8 encoding of 0x4840 */
	if (in[0] == 0xe4 && in[1] == 0xa1 && in[2] == 0x80)
		in += 3;

	while (*in) {
		guint8 ch = *in;
		if ((ch == 0xe3 && in[1] >= 0xa0) || (ch == 0xe4 && in[1] < 0xa0)) {
			*q++ = msi_base64_decode(in[2] & 0x7f);
			*q++ = msi_base64_decode(in[1] ^ 0xa0);
			in += 3;
			count += 2;
			continue;
		}
		if (ch == 0xe4 && in[1] == 0xa0) {
			*q++ = msi_base64_decode(in[2] & 0x7f);
			in += 3;
			count++;
			continue;
		}
		*q++ = *in++;
		if (ch >= 0xc1)
			*q++ = *in++;
		if (ch >= 0xe0)
			*q++ = *in++;
		if (ch >= 0xf0)
			*q++ = *in++;
		count++;
	}
	*q = 0;
}

/*
 * Sorry if this code looks a bit silly, but that seems
 * to be the best solution so far...
 */
static gint msi_cmp(gpointer a, gpointer b)
{
	glong anc = 0, bnc = 0;
	gchar *pa = (gchar*)g_utf8_to_utf16(a, -1, NULL, &anc, NULL);
	gchar *pb = (gchar*)g_utf8_to_utf16(b, -1, NULL, &bnc, NULL);
	gint diff;

	diff = memcmp(pa, pb, MIN(2*anc, 2*bnc));
	/* apparently the longer wins */
	if (diff == 0)
		return 2*anc > 2*bnc ? 1 : -1;
	g_free(pa);
	g_free(pb);
	return diff;
}

/*
 * msi_sorted_infile_children returns a sorted list of all
 * of the children of the given infile. The children are
 * sorted according to the msi_cmp.
 *
 * The returned list must be freed with g_slist_free_full.
 */
static GSList *msi_sorted_infile_children(GsfInfile *infile)
{
	GSList *sorted = NULL;
	gchar decoded[0x40];
	int i;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const gchar *name = gsf_input_name(child);
		msi_decode((const guint8*)name, decoded);

		if (g_strcmp0(decoded, "\05DigitalSignature") &&
				g_strcmp0(decoded, "\05MsiDigitalSignatureEx"))
			sorted = g_slist_insert_sorted(sorted, (gpointer)g_strdup(name), (GCompareFunc)msi_cmp);

		g_object_unref(child);
	}
	return sorted;
}

/*
 * msi_prehash_utf16_name converts an UTF-8 representation of
 * an MSI filename to its on-disk UTF-16 representation and
 * writes it to the hash BIO.  It is used when calculating the
 * pre-hash used for MsiDigitalSignatureEx signatures in MSI files.
 */
static gboolean msi_prehash_utf16_name(gchar *name, BIO *hash)
{
	glong chars_written = 0;

	gchar *u16name = (gchar*)g_utf8_to_utf16(name, -1, NULL, &chars_written, NULL);
	if (u16name == NULL) {
		return FALSE; /* FAILED */
	}
	BIO_write(hash, u16name, 2*chars_written);
	g_free(u16name);
	return TRUE;
}

/*
 * msi_prehash calculates the pre-hash used for 'MsiDigitalSignatureEx'
 * signatures in MSI files.  The pre-hash hashes only metadata (file names,
 * file sizes, creation times and modification times), whereas the basic
 * 'DigitalSignature' MSI signature only hashes file content.
 *
 * The hash is written to the hash BIO.
 */
static gboolean msi_prehash(GsfInfile *infile, gchar *dirname, BIO *hash)
{
	GSList *sorted, *current;
	guint8 classid[16], zeroes[8];
	gboolean is_dir;
	gsf_off_t size;
	guint32 sizebuf;
	bool ret = FALSE;

	memset(&zeroes, 0, sizeof(zeroes));
	gsf_infile_msole_get_class_id(GSF_INFILE_MSOLE(infile), classid);

	if (dirname != NULL) {
		if (!msi_prehash_utf16_name(dirname, hash))
			return ret; /* FAILED */
	}
	BIO_write(hash, classid, sizeof(classid));
	BIO_write(hash, zeroes, 4);
	if (dirname != NULL) {
		/*
		 * Creation time and modification time for the root directory.
		 * These are always zero. The ctime and mtime of the actual
		 * file itself takes precedence.
		 */
		BIO_write(hash, zeroes, 8); /* ctime as Windows FILETIME */
		BIO_write(hash, zeroes, 8); /* mtime as Windows FILETIME */
	}
	sorted = msi_sorted_infile_children(infile);
	for (current = sorted; current; current = g_slist_next(current)) {
		gchar *name = current->data;
		GsfInput *child =  gsf_infile_child_by_name(infile, name);
		if (child == NULL)
			continue;
		is_dir = GSF_IS_INFILE(child) && gsf_infile_num_children(GSF_INFILE(child)) > 0;
		if (is_dir) {
			if (!msi_prehash(GSF_INFILE(child), name, hash)) {
				g_object_unref(child);
				goto out;
			}
		} else {
			if (!msi_prehash_utf16_name(name, hash)) {
				g_object_unref(child);
				goto out;
			}
			/*
			 * File size.
			 */
			size = gsf_input_remaining(child);
			sizebuf = GUINT32_TO_LE((guint32)size);
			BIO_write(hash, &sizebuf, sizeof(sizebuf));
			/*
			 * Reserved - must be 0. Corresponds to
			 * offset 0x7c..0x7f in the CDFv2 file.
			 */
			BIO_write(hash, zeroes, 4);
			/*
			 * Creation time and modification time
			 * as Windows FILETIMEs. We keep them
			 * zeroed, because libgsf doesn't seem
			 * to support outputting them.
			 */
			BIO_write(hash, zeroes, 8); /* ctime as Windows FILETIME */
			BIO_write(hash, zeroes, 8); /* mtime as Windows FILETIME */
		}
		g_object_unref(child);
	}
	ret = TRUE;
out:
	g_slist_free_full(sorted, g_free);
	return ret;
}

/**
 * msi_handle_dir performs a direct copy of the input MSI file in infile to a new
 * output file in outfile.  While copying, it also writes all file content to the
 * hash BIO in order to calculate a 'basic' hash that can be used for an MSI
 * 'DigitalSignature' hash.
 *
 * msi_handle_dir is hierarchy aware: if any subdirectories are found, they will be
 * visited, copied and hashed as well.
 */
static gboolean msi_handle_dir(GsfInfile *infile, GsfOutfile *outole, BIO *hash)
{
	guint8 classid[16];
	GSList *sorted, *current;
	GsfOutput *outchild = NULL;
	gboolean is_dir;
	gsf_off_t size;
	guint8 const *data;
	bool ret = FALSE;

	gsf_infile_msole_get_class_id(GSF_INFILE_MSOLE(infile), classid);
	if (outole != NULL)
		gsf_outfile_msole_set_class_id(GSF_OUTFILE_MSOLE(outole), classid);

	sorted = msi_sorted_infile_children(infile);
	for (current = sorted; current; current = g_slist_next(current)) {
		gchar *name = current->data;
		GsfInput *child =  gsf_infile_child_by_name(infile, name);
		if (child == NULL)
			continue;
		is_dir = GSF_IS_INFILE(child) && gsf_infile_num_children(GSF_INFILE(child)) > 0;
		if (outole != NULL)
			outchild = gsf_outfile_new_child(outole, name, is_dir);
		if (is_dir) {
			if (!msi_handle_dir(GSF_INFILE(child), GSF_OUTFILE(outchild), hash)) {
				gsf_output_close(outchild);
				g_object_unref(outchild);
				g_object_unref(child);
				goto out;
			}
		} else {
			while (gsf_input_remaining(child) > 0) {
				size = MIN(gsf_input_remaining(child), 4096);
				data = gsf_input_read(child, size, NULL);
				BIO_write(hash, data, size);
				if (outchild != NULL && !gsf_output_write(outchild, size, data)) {
					gsf_output_close(outchild);
					g_object_unref(outchild);
					g_object_unref(child);
					goto out;
				}
			}
		}
		if (outchild != NULL) {
			gsf_output_close(outchild);
			g_object_unref(outchild);
		}
		g_object_unref(child);
	}
	BIO_write(hash, classid, sizeof(classid));
	ret = TRUE;
out:
	g_slist_free_full(sorted, g_free);
	return ret;
}

/*
 * msi_verify_pkcs7 is a helper function for msi_verify_file.
 * It exists to make it easier to implement verification of nested signatures.
 */
static int msi_verify_pkcs7(SIGNATURE *signature, GsfInfile *infile, unsigned char *exdata,
		size_t exlen, GLOBAL_OPTIONS *options)
{
	int ret = 1, mdtype = -1, mdok, exok;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
#ifdef GSF_CAN_READ_MSI_METADATA
	unsigned char cexmdbuf[EVP_MAX_MD_SIZE];
#endif
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	const EVP_MD *md;
	BIO *hash, *prehash;

	if (is_indirect_data_signature(signature->p7)) {
		ASN1_STRING *astr = signature->p7->d.sign->contents->d.other->value.sequence;
		const unsigned char *p = astr->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, astr->length);
		if (idc) {
			if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
				mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
				memcpy(mdbuf, idc->messageDigest->digest->data, idc->messageDigest->digest->length);
			}
			SpcIndirectDataContent_free(idc);
		}
	}
	if (mdtype == -1) {
		printf("Failed to extract current message digest\n\n");
		goto out;
	}
	printf("Message digest algorithm         : %s\n", OBJ_nid2sn(mdtype));
	md = EVP_get_digestbynid(mdtype);
	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, md);
	BIO_push(hash, BIO_new(BIO_s_null()));
	if (exdata) {
		/*
		 * Until libgsf can read more MSI metadata, we can't
		 * really verify them by plowing through the file.
		 * Verifying files signed by osslsigncode itself works,
		 * though!
		 *
		 * For now, the compromise is to use the hash given
		 * by the file, which is equivalent to verifying a
		 * non-MsiDigitalSignatureEx signature from a security
		 * perspective, because we'll only be calculating the
		 * file content hashes ourselves.
		 */
#ifdef GSF_CAN_READ_MSI_METADATA
		prehash = BIO_new(BIO_f_md());
		BIO_set_md(prehash, md);
		BIO_push(prehash, BIO_new(BIO_s_null()));

		if (!msi_prehash(infile, NULL, prehash)) {
			printf("Failed to calculate pre-hash used for MsiDigitalSignatureEx\n\n");
			BIO_free_all(hash);
			BIO_free_all(prehash);
			goto out;
		}
		BIO_gets(prehash, (char*)cexmdbuf, EVP_MAX_MD_SIZE);
		BIO_free_all(prehash);
		BIO_write(hash, (char*)cexmdbuf, EVP_MD_size(md));
#else
		BIO_write(hash, (char *)exdata, EVP_MD_size(md));
#endif
	}
	if (!msi_handle_dir(infile, NULL, hash)) {
		printf("Failed to write a new output file\n\n");
		BIO_free_all(hash);
		goto out;
	}
	BIO_gets(hash, (char*)cmdbuf, EVP_MAX_MD_SIZE);
	BIO_free_all(hash);
	tohex(cmdbuf, hexbuf, EVP_MD_size(md));
	printf("Calculated DigitalSignature      : %s", hexbuf);
	mdok = !memcmp(mdbuf, cmdbuf, EVP_MD_size(md));
	if (!mdok) {
		tohex(mdbuf, hexbuf, EVP_MD_size(md));
		printf("    MISMATCH!!!\n\t\t\tFILE HAS : %s\n\n", hexbuf);
		printf("Signature verification: failed\n\n");
		goto out;
	} else
		printf("\n");

#ifdef GSF_CAN_READ_MSI_METADATA
	if (exdata) {
		tohex(cexmdbuf, hexbuf, EVP_MD_size(md));
		exok = !memcmp(exdata, cexmdbuf, MIN((size_t)EVP_MD_size(md), exlen));
		printf("Calculated MsiDigitalSignatureEx : %s", hexbuf);
		if (!exok) {
			tohex(exdata, hexbuf, MIN((size_t)EVP_MD_size(md), exlen));
			printf("    MISMATCH!!!\n\t\t\tFILE HAS : %s\n\n", hexbuf);
			printf("Signature verification: failed\n\n");
			goto out;
		} else
			printf("\n");
	}
#endif

	ret = verify_signature(signature, options);
out:
	if (!ret)
		ERR_print_errors_fp(stdout);
	return ret;
}

/*
 * msi_get_child returns the first child that its value name matches the pattern.
 * The returned input stream must be unrefed.
*/

static GsfInput *msi_get_child(GsfInfile *infile, const char *pattern)
{
	gchar decoded[0x40];
	int i;

	for (i = 0; i < gsf_infile_num_children(infile); i++) {
		GsfInput *child = gsf_infile_child_by_index(infile, i);
		const guint8 *name = (const guint8*)gsf_input_name(child);
		msi_decode(name, decoded);
		if (!g_strcmp0(decoded, pattern))
			return child;
		else
			g_object_unref(child);
	}
	return NULL;
}

/*
 * msi_verify_file checks whether or not the signature of infile is valid.
 */
static int msi_verify_file(GsfInfile *infile, GLOBAL_OPTIONS *options)
{
	GsfInput *sig, *exsig;
	unsigned char *exdata = NULL;
	unsigned char *indata = NULL;
	int i, ret = 1;
	PKCS7 *p7 = NULL;
	unsigned long inlen, exlen = 0;
	const unsigned char *blob;
	STACK_OF(SIGNATURE) *signatures;
	SIGNATURE *signature = NULL;

	sig = msi_get_child(infile, "\05DigitalSignature");
	if (sig == NULL) {
		printf("MSI file has no signature\n\n");
		return 1; /* FAILED */
	}

	signatures = sk_SIGNATURE_new_null();

	inlen = (unsigned long) gsf_input_remaining(sig);
	indata = OPENSSL_malloc(inlen);
	if (gsf_input_read(sig, inlen, indata) == NULL) {
		goto out;
	}
	exsig = msi_get_child(infile, "\05MsiDigitalSignatureEx");
	if (exsig != NULL) {
		exlen = (unsigned long) gsf_input_remaining(exsig);
		exdata = OPENSSL_malloc(exlen);
		if (gsf_input_read(exsig, exlen, exdata) == NULL) {
			g_object_unref(exsig);
			goto out;
		}
		g_object_unref(exsig);
	}
	blob = (unsigned char *)indata;
	p7 = d2i_PKCS7(NULL, &blob, inlen);
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
		printf("Signature Index: %d %s\n", i, i==0 ? " (Primary Signature)" : "");
		signature = sk_SIGNATURE_value(signatures, i);
		ret &= msi_verify_pkcs7(signature, infile, exdata, exlen, options);
		if (signature->timestamp) {
			CMS_ContentInfo_free(signature->timestamp);
			ERR_clear_error();
		}
		PKCS7_free(signature->p7);
		OPENSSL_free(signature);
	}
	printf("Number of verified signatures: %d\n", i);
out:
	g_object_unref(sig);
	sk_SIGNATURE_free(signatures);
	OPENSSL_free(indata);
	OPENSSL_free(exdata);
	return ret;
}

static int msi_extract_dse(GsfInfile *infile, unsigned char **dsebuf,
	unsigned long *dselen, int *has_dse)
{
	GsfInput *exsig;
	unsigned char *buf = NULL;
	gsf_off_t size = 0;

	exsig = msi_get_child(infile, "\05MsiDigitalSignatureEx");
	if (exsig == NULL)
		return FALSE; /* FAILED */
	if (has_dse != NULL) {
		*has_dse = 1;
	}
	size = gsf_input_remaining(exsig);
	if (dselen != NULL) {
		*dselen = (unsigned long) size;
	}
	if (dsebuf != NULL) {
		buf = OPENSSL_malloc(size);
		if (gsf_input_read(exsig, size, buf) == NULL) {
			g_object_unref(exsig);
			return FALSE; /* FAILED */
		}
		*dsebuf = buf;
	}
	g_object_unref(exsig);
	return TRUE; /* OK */
}

/*
 * msi_extract_signature_to_file extracts the MSI DigitalSignaure from infile
 * to a file at the path given by outfile.
 */
static int msi_extract_signature_to_file(GsfInfile *infile, GLOBAL_OPTIONS *options)
{
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	GsfInput *sig, *exsig;
	unsigned char *exdata = NULL;
	unsigned long exlen = 0;
	BIO *outdata;
	int ret = 1;

	sig = msi_get_child(infile, "\05DigitalSignature");
	if (sig == NULL) {
		printf("MSI file has no signature\n\n");
		return 1; /* FAILED */
	}
	/* Create outdata DER file */
#ifdef WIN32
	if (!access(options->outfile, R_OK)) {
		/* outdata file exists */
		printf("Failed to create file: %s\n", options->outfile);
		goto out;
	}
#endif
	outdata = BIO_new_file(options->outfile, FILE_CREATE_MODE);
	if (outdata == NULL) {
		printf("Failed to create file: %s\n", options->outfile);
		goto out;
	}
	while (gsf_input_remaining(sig) > 0) {
		gsf_off_t size = MIN(gsf_input_remaining(sig), 4096);
		guint8 const *data = gsf_input_read(sig, size, NULL);
		BIO_write(outdata, data, size);
	}

	exsig = msi_get_child(infile, "\05MsiDigitalSignatureEx");
	if (exsig != NULL) {
		exlen = (unsigned long) gsf_input_remaining(exsig);
		if (exlen > EVP_MAX_MD_SIZE) {
			printf("MsiDigitalSignatureEx is larger than EVP_MAX_MD_SIZE\n");
			g_object_unref(exsig);
			goto out;
		}
		exdata = OPENSSL_malloc(exlen);
		if (gsf_input_read(exsig, exlen, exdata) == NULL) {
			printf("Unable to read MsiDigitalSignatureEx\n");
			OPENSSL_free(exdata);
			g_object_unref(exsig);
			goto out;
		}
		tohex(exdata, hexbuf, exlen);
		printf("Note: MSI includes a MsiDigitalSignatureEx section\n");
		printf("MsiDigitalSignatureEx pre-hash: %s\n", hexbuf);
		OPENSSL_free(exdata);
		g_object_unref(exsig);
	}

	ret = 0; /* OK */
out:
	g_object_unref(sig);
	if (outdata)
		BIO_free_all(outdata);
	return ret;
}

static PKCS7 *msi_extract_signature_to_pkcs7(GsfInfile *infile)
{
	GsfInput *sig;
	PKCS7 *p7 = NULL;
	u_char *buf = NULL;
	gsf_off_t size = 0;
	const unsigned char *p7buf;

	sig = msi_get_child(infile, "\05DigitalSignature");
	if (sig == NULL) {
		printf("MSI file has no signature\n\n");
		return NULL; /* FAILED */
	}
	size = gsf_input_remaining(sig);
	buf = OPENSSL_malloc(size);
	if (gsf_input_read(sig, size, buf) == NULL)
		goto out;
	p7buf = buf;
	p7 = d2i_PKCS7(NULL, &p7buf, size);

out:
	g_object_unref(sig);
	OPENSSL_free(buf);
	return p7;
}

static int msi_extract_file(GsfInfile *ole, GLOBAL_OPTIONS *options)
{
	int ret = 0;
	BIO *outdata;
	PKCS7 *sig;

	if (options->output_pkcs7) {
		sig = msi_extract_signature_to_pkcs7(ole);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		/* Create outdata PEM file */
#ifdef WIN32
		if (!access(options->outfile, R_OK)) {
			/* outdata file exists */
			printf("Failed to create file: %s\n", options->outfile);
			PKCS7_free(sig);
			return 1; /* FAILED */
		}
#endif
		outdata = BIO_new_file(options->outfile, FILE_CREATE_MODE);
		if (outdata == NULL) {
			printf("Failed to create file: %s\n", options->outfile);
			PKCS7_free(sig);
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(outdata, sig);
		BIO_free_all(outdata);
		PKCS7_free(sig);
	} else
		ret = msi_extract_signature_to_file(ole, options);

	return ret;
}

/*
 * Perform a sanity check for the MsiDigitalSignatureEx section.
 * If the file we're attempting to sign has an MsiDigitalSignatureEx
 * section, we can't add a nested signature of a different MD type
 * without breaking the initial signature.
 */
static int msi_check_MsiDigitalSignatureEx(GsfInfile *ole, const EVP_MD *md)
{
	unsigned long dselen = 0;
	int mdlen, has_dse = 0;

	if (!msi_extract_dse(ole, NULL, &dselen, &has_dse) && has_dse) {
		printf("Unable to extract MsiDigitalSignatureEx section\n\n");
		return 0; /* FAILED */
	}
	if (has_dse) {
		mdlen = EVP_MD_size(md);
		if (dselen != (unsigned long)mdlen) {
			printf("Unable to add nested signature with a different MD type (-h parameter) "
				"than what exists in the MSI file already.\nThis is due to the presence of "
				"MsiDigitalSignatureEx (-add-msi-dse parameter).\n\n");
				return 0; /* FAILED */
		}
	}
	return 1; /* OK */
}

/*
 * MsiDigitalSignatureEx is an enhanced signature type that
 * can be used when signing MSI files.  In addition to
 * file content, it also hashes some file metadata, specifically
 * file names, file sizes, creation times and modification times.
 *
 * The file content hashing part stays the same, so the
 * msi_handle_dir() function can be used across both variants.
 *
 * When an MsiDigitalSigntaureEx section is present in an MSI file,
 * the meaning of the DigitalSignature section changes:  Instead
 * of being merely a file content hash (as what is output by the
 * msi_handle_dir() function), it is now hashes both content
 * and metadata.
 *
 * Here is how it works:
 *
 * First, a "pre-hash" is calculated. This is the "metadata" hash.
 * It iterates over the files in the MSI in the same order as the
 * file content hashing method would - but it only processes the
 * metadata.
 *
 * Once the pre-hash is calculated, a new hash is created for
 * calculating the hash of the file content.  The output of the
 * pre-hash is added as the first element of the file content hash.
 *
 * After the pre-hash is written, what follows is the "regular"
 * stream of data that would normally be written when performing
 * file content hashing.
 *
 * The output of this hash, which combines both metadata and file
 * content, is what will be output in signed form to the
 * DigitalSignature section when in 'MsiDigitalSignatureEx' mode.
 *
 * As mentioned previously, this new mode of operation is signalled
 * by the presence of a 'MsiDigitalSignatureEx' section in the MSI
 * file.  This section must come after the 'DigitalSignature'
 * section, and its content must be the output of the pre-hash
 * ("metadata") hash.
 */

static int msi_calc_MsiDigitalSignatureEx(GsfInfile *ole, const EVP_MD *md,
			BIO *hash, GSF_PARAMS *gsfparams)
{
	BIO *prehash;

	prehash = BIO_new(BIO_f_md());
	BIO_set_md(prehash, md);
	BIO_push(prehash, BIO_new(BIO_s_null()));

	if (!msi_prehash(ole, NULL, prehash)) {
		printf("Unable to calculate MSI pre-hash ('metadata') hash\n");
		BIO_free_all(prehash);
		return 0; /* FAILED */
	}
	gsfparams->p_msiex = OPENSSL_malloc(EVP_MAX_MD_SIZE);
	gsfparams->len_msiex = BIO_gets(prehash, (char*)gsfparams->p_msiex, EVP_MAX_MD_SIZE);
	BIO_write(hash, gsfparams->p_msiex, gsfparams->len_msiex);
	BIO_free_all(prehash);
	return 1; /* OK */
}

static int msi_add_DigitalSignature(GsfOutfile *outole, u_char *p, int len)
{
	GsfOutput *child;
	int ret = 1;

	child = gsf_outfile_new_child(outole, "\05DigitalSignature", FALSE);
	if (!gsf_output_write(child, len, p))
		ret = 0;
	gsf_output_close(child);
	g_object_unref(child);
	return ret;
}

static int msi_add_MsiDigitalSignatureEx(GsfOutfile *outole, GSF_PARAMS *gsfparams)
{
	GsfOutput *child;
	int ret = 1;

	child = gsf_outfile_new_child(outole, "\05MsiDigitalSignatureEx", FALSE);
	if (!gsf_output_write(child, gsfparams->len_msiex, gsfparams->p_msiex))
		ret = 0;
	gsf_output_close(child);
	g_object_unref(child);
	OPENSSL_free(gsfparams->p_msiex);
	return ret;
}

#endif


/*
 * PE file support
 */
static void pe_calc_digest(char *indata, const EVP_MD *md, unsigned char *mdbuf, FILE_HEADER *header)
{
	BIO *bio = NULL;
	static unsigned char bfb[16*1024*1024];
	EVP_MD_CTX *mdctx;
	size_t n;
	int l;

	bio = BIO_new_mem_buf(indata, header->sigpos + header->siglen);
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit(mdctx, md);

	memset(mdbuf, 0, EVP_MAX_MD_SIZE);

	(void)BIO_seek(bio, 0);
	BIO_read(bio, bfb, header->header_size + 88);
	EVP_DigestUpdate(mdctx, bfb, header->header_size + 88);
	BIO_read(bio, bfb, 4);
	BIO_read(bio, bfb, 60 + header->pe32plus * 16);
	EVP_DigestUpdate(mdctx, bfb, 60 + header->pe32plus * 16);
	BIO_read(bio, bfb, 8);

	n = header->header_size + 88 + 4 + 60 + header->pe32plus * 16 + 8;
	while (n < header->sigpos) {
		size_t want = header->sigpos - n;
		if (want > sizeof(bfb))
			want = sizeof(bfb);
		l = BIO_read(bio, bfb, want);
		if (l <= 0)
			break;
		EVP_DigestUpdate(mdctx, bfb, l);
		n += l;
	}
	EVP_DigestFinal(mdctx, mdbuf, NULL);
	EVP_MD_CTX_free(mdctx);
	BIO_free(bio);
}

static void pe_extract_page_hash(SpcAttributeTypeAndOptionalValue *obj,
	unsigned char **ph, size_t *phlen, int *phtype)
{
	const unsigned char *blob;
	SpcPeImageData *id;
	SpcSerializedObject *so;
	size_t l, l2;
	char buf[128];

	*phlen = 0;
	blob = obj->value->value.sequence->data;
	id = d2i_SpcPeImageData(NULL, &blob, obj->value->value.sequence->length);
	if (id == NULL)
		return;
	if (id->file->type != 1) {
		SpcPeImageData_free(id);
		return;
	}
	so = id->file->value.moniker;
	if (so->classId->length != sizeof(classid_page_hash) ||
		memcmp(so->classId->data, classid_page_hash, sizeof (classid_page_hash))) {
		SpcPeImageData_free(id);
		return;
	}
	/* skip ASN.1 SET hdr */
	l = asn1_simple_hdr_len(so->serializedData->data, so->serializedData->length);
	blob = so->serializedData->data + l;
	obj = d2i_SpcAttributeTypeAndOptionalValue(NULL, &blob, so->serializedData->length - l);
	SpcPeImageData_free(id);
	if (!obj)
		return;

	*phtype = 0;
	buf[0] = 0x00;
	OBJ_obj2txt(buf, sizeof(buf), obj->type, 1);
	if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V1)) {
		*phtype = NID_sha1;
	} else if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V2)) {
		*phtype = NID_sha256;
	} else {
		SpcAttributeTypeAndOptionalValue_free(obj);
		return;
	}
	/* Skip ASN.1 SET hdr */
	l2 = asn1_simple_hdr_len(obj->value->value.sequence->data, obj->value->value.sequence->length);
	/* Skip ASN.1 OCTET STRING hdr */
	l = asn1_simple_hdr_len(obj->value->value.sequence->data + l2, obj->value->value.sequence->length - l2);
	l += l2;
	*phlen = obj->value->value.sequence->length - l;
	*ph = OPENSSL_malloc(*phlen);
	memcpy(*ph, obj->value->value.sequence->data + l, *phlen);
	SpcAttributeTypeAndOptionalValue_free(obj);
}

static int pe_verify_pkcs7(SIGNATURE *signature, char *indata, FILE_HEADER *header,
			GLOBAL_OPTIONS *options)
{
	int ret = 1, mdok, mdtype = -1, phtype = -1;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	unsigned char *ph = NULL;
	size_t phlen = 0;
	const EVP_MD *md;

	if (is_indirect_data_signature(signature->p7)) {
		ASN1_STRING *astr = signature->p7->d.sign->contents->d.other->value.sequence;
		const unsigned char *p = astr->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, astr->length);
		if (idc) {
			pe_extract_page_hash(idc->data, &ph, &phlen, &phtype);
			if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
				mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
				memcpy(mdbuf, idc->messageDigest->digest->data, idc->messageDigest->digest->length);
			}
			SpcIndirectDataContent_free(idc);
		}
	}
	if (mdtype == -1) {
		printf("Failed to extract current message digest\n\n");
		goto out;
	}
	printf("Message digest algorithm  : %s\n", OBJ_nid2sn(mdtype));

	md = EVP_get_digestbynid(mdtype);
	tohex(mdbuf, hexbuf, EVP_MD_size(md));
	printf("Current message digest    : %s\n", hexbuf);

	pe_calc_digest(indata, md, cmdbuf, header);
	tohex(cmdbuf, hexbuf, EVP_MD_size(md));
	mdok = !memcmp(mdbuf, cmdbuf, EVP_MD_size(md));
	printf("Calculated message digest : %s%s\n\n", hexbuf, mdok ? "" : "    MISMATCH!!!");
	if (!mdok) {
		printf("Signature verification: failed\n\n");
		goto out;
	}

	if (phlen > 0) {
		size_t cphlen = 0;
		unsigned char *cph;

		printf("Page hash algorithm  : %s\n", OBJ_nid2sn(phtype));
		tohex(ph, hexbuf, (phlen < 32) ? phlen : 32);
		printf("Page hash            : %s ...\n", hexbuf);
		cph = pe_calc_page_hash(indata, header->header_size, header->pe32plus, header->sigpos, phtype, &cphlen);
		tohex(cph, hexbuf, (cphlen < 32) ? cphlen : 32);
		mdok = (phlen = cphlen) && !memcmp(ph, cph, phlen);
		OPENSSL_free(cph);
		printf("Calculated page hash : %s ...%s\n\n", hexbuf, mdok ? "" : "    MISMATCH!!!");
		if (!mdok) {
			printf("Signature verification: failed\n\n");
			goto out;
		}
	}

	ret = verify_signature(signature, options);
out:
	if (!ret)
		ERR_print_errors_fp(stdout);
	OPENSSL_free(ph);
	return ret;
}

/*
 * pe_extract_existing_pkcs7 retrieves a decoded PKCS7 struct
 * corresponding to the existing signature of the PE file.
 */
static PKCS7 *pe_extract_existing_pkcs7(char *indata, FILE_HEADER *header)
{
	size_t pos = 0;
	PKCS7 *p7 = NULL;

	while (pos < header->siglen) {
		size_t l = GET_UINT32_LE(indata + header->sigpos + pos);
		unsigned short certrev  = GET_UINT16_LE(indata + header->sigpos + pos + 4);
		unsigned short certtype = GET_UINT16_LE(indata + header->sigpos + pos + 6);
		if (certrev == WIN_CERT_REVISION_2 && certtype == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
			const unsigned char *blob = (unsigned char*)indata + header->sigpos + pos + 8;
			p7 = d2i_PKCS7(NULL, &blob, l - 8);
		}
		if (l%8)
			l += (8 - l%8);
		pos += l;
	}
	return p7;
}

static int pe_verify_file(char *indata, FILE_HEADER *header, GLOBAL_OPTIONS *options)
{
	int i, peok = 1, ret = 1;
	BIO *bio;
	unsigned int real_pe_checksum;
	PKCS7 *p7;
	STACK_OF(SIGNATURE) *signatures;
	SIGNATURE *signature = NULL;

	if (header->siglen == 0)
		header->siglen = header->fileend;

	signatures = sk_SIGNATURE_new_null();

	/* check PE checksum */
	printf("Current PE checksum   : %08X\n", header->pe_checksum);
	bio = BIO_new_mem_buf(indata, header->sigpos + header->siglen);
	real_pe_checksum = pe_calc_checksum(bio, header);
	BIO_free(bio);
	if (header->pe_checksum && header->pe_checksum != real_pe_checksum)
		peok = 0;
	printf("Calculated PE checksum: %08X%s\n\n", real_pe_checksum, peok ? "" : "    MISMATCH!!!");

	if (header->sigpos == 0) {
		printf("No signature found\n\n");
		goto out;
	}
	p7 = pe_extract_existing_pkcs7(indata, header);
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
		printf("Signature Index: %d %s\n", i, i==0 ? " (Primary Signature)" : "");
		signature = sk_SIGNATURE_value(signatures, i);
		ret &= pe_verify_pkcs7(signature, indata, header, options);
		if (signature->timestamp) {
			CMS_ContentInfo_free(signature->timestamp);
			ERR_clear_error();
		}
		PKCS7_free(signature->p7);
		OPENSSL_free(signature);
	}
	printf("Number of verified signatures: %d\n", i);
out:
	sk_SIGNATURE_free(signatures);
	return ret;
}

static int pe_extract_file(char *indata, FILE_HEADER *header, BIO *outdata, int output_pkcs7)
{
	int ret = 0;
	PKCS7 *sig;

	(void)BIO_reset(outdata);
	if (output_pkcs7) {
		sig = pe_extract_existing_pkcs7(indata, header);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(outdata, sig);
		PKCS7_free(sig);
	} else
		ret = !BIO_write(outdata, indata + header->sigpos, header->siglen);

	return ret;
}

static int pe_verify_header(char *indata, char *infile, size_t filesize, FILE_HEADER *header)
{
	int ret = 1;

	if (filesize < 64) {
		printf("Corrupt DOS file - too short: %s\n", infile);
		ret = 0; /* FAILED */
	}
	header->header_size = GET_UINT32_LE(indata+60);
	if (filesize < header->header_size + 160) {
		printf("Corrupt DOS file - too short: %s\n", infile);
		ret = 0; /* FAILED */
	}
	if (memcmp(indata + header->header_size, "PE\0\0", 4)) {
		printf("Unrecognized DOS file type: %s\n", infile);
		ret = 0; /* FAILED */
	}
	header->magic = GET_UINT16_LE(indata + header->header_size + 24);
	if (header->magic == 0x20b) {
		header->pe32plus = 1;
	} else if (header->magic == 0x10b) {
		header->pe32plus = 0;
	} else {
		printf("Corrupt PE file - found unknown magic %04X: %s\n", header->magic, infile);
		ret = 0; /* FAILED */
	}
	header->pe_checksum = GET_UINT32_LE(indata + header->header_size + 88);
	header->nrvas = GET_UINT32_LE(indata + header->header_size + 116 + header->pe32plus * 16);
	if (header->nrvas < 5) {
		printf("Can not handle PE files without certificate table resource: %s\n", infile);
		ret = 0; /* FAILED */
	}
	header->sigpos = GET_UINT32_LE(indata + header->header_size + 152 + header->pe32plus * 16);
	header->siglen = GET_UINT32_LE(indata + header->header_size + 152 + header->pe32plus * 16 + 4);

	/* Since fix for MS Bulletin MS12-024 we can really assume
	   that signature should be last part of file */
	if (header->sigpos > 0 && header->sigpos < filesize && header->sigpos + header->siglen != filesize) {
		printf("Corrupt PE file - current signature not at end of file: %s\n", infile);
		ret = 0; /* FAILED */
	}
	return ret;
}

static void pe_modify_header(char *indata, FILE_HEADER *header, BIO *hash, BIO *outdata)
{
	int len = 0, i;
	static char buf[64*1024];

	i = header->header_size + 88;
	BIO_write(hash, indata, i);
	memset(buf, 0, 4);
	BIO_write(outdata, buf, 4); /* zero out checksum */
	i += 4;
	BIO_write(hash, indata + i, 60 + header->pe32plus * 16);
	i += 60 + header->pe32plus * 16;
	memset(buf, 0, 8);
	BIO_write(outdata, buf, 8); /* zero out sigtable offset + pos */
	i += 8;
	BIO_write(hash, indata + i, header->fileend - i);

	/* pad (with 0's) pe file to 8 byte boundary */
	len = 8 - header->fileend % 8;
	if (len > 0 && len != 8) {
		memset(buf, 0, len);
		BIO_write(hash, buf, len);
		header->fileend += len;
	}
}

/*
 * CAB file support
 * https://www.file-recovery.com/cab-signature-format.htm
 */

static int cab_verify_header(char *indata, char *infile, size_t filesize, FILE_HEADER *header)
{
	int ret = 1;
	size_t reserved;

	if (filesize < 44) {
		printf("Corrupt cab file - too short: %s\n", infile);
		ret = 0; /* FAILED */
	}
	reserved = GET_UINT32_LE(indata + 4);
	if (reserved) {
		printf("Reserved1: 0x%08lX\n", reserved);
		ret = 0; /* FAILED */
	}
	/* flags specify bit-mapped values that indicate the presence of optional data */
	header->flags = GET_UINT16_LE(indata + 30);
#if 1
	if (header->flags & FLAG_PREV_CABINET) {
		/* FLAG_NEXT_CABINET works */
		printf("Multivolume cabinet file is unsupported: flags 0x%04lX\n", header->flags);
		ret = 0; /* FAILED */
	}
#endif
	if (header->flags & FLAG_RESERVE_PRESENT) {
		/*
		* Additional headers is located at offset 36 (cbCFHeader, cbCFFolder, cbCFData);
		* size of header (4 bytes, little-endian order) must be 20 (checkpoint).
		*/
		header->header_size = GET_UINT32_LE(indata + 36);
		if (header->header_size != 20) {
			printf("Additional header size: 0x%08lX\n", header->header_size);
			ret = 0; /* FAILED */
		}
		reserved = GET_UINT32_LE(indata + 40);
		if (reserved != 0x00100000) {
			printf("abReserved: 0x%08lX\n", reserved);
			ret = 0; /* FAILED */
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
		if (header->sigpos < filesize && header->sigpos + header->siglen != filesize) {
			printf("Additional data offset:\t%lu bytes\nAdditional data size:\t%lu bytes\n",
					header->sigpos, header->siglen);
			printf("File size:\t\t%lu bytes\n", filesize);
			ret = 0; /* FAILED */
		}
	}
	return ret;
}

static void cab_calc_digest(char *indata, const EVP_MD *md, unsigned char *mdbuf, size_t offset)
{
	BIO *bio;
	size_t coffFiles, nfolders, flags;
	static unsigned char bfb[16*1024*1024];
	EVP_MD_CTX *mdctx;
	int l;

	bio = BIO_new_mem_buf(indata, offset);
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit(mdctx, md);
	memset(mdbuf, 0, EVP_MAX_MD_SIZE);
	(void)BIO_seek(bio, 0);

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_read(bio, bfb, 4);
	EVP_DigestUpdate(mdctx, bfb, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_read(bio, bfb, 4);
	/*
	 * u4 cbCabinet - size of this cabinet file in bytes: 8-11
	 * u4 reserved2 00000000: 12-15
	 */
	BIO_read(bio, bfb, 8);
	EVP_DigestUpdate(mdctx, bfb, 8);
	 /* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	BIO_read(bio, bfb, 4);
	coffFiles = GET_UINT32_LE(bfb);
	EVP_DigestUpdate(mdctx, bfb, 4);
	/*
	 * u4 reserved3 00000000: 20-23
	 * u1 versionMinor 03: 24
	 * u1 versionMajor 01: 25
	 */
	BIO_read(bio, bfb, 6);
	EVP_DigestUpdate(mdctx, bfb, 6);
	/* u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27 */
	BIO_read(bio, bfb, 2);
	nfolders = GET_UINT16_LE(bfb);
	EVP_DigestUpdate(mdctx, bfb, 2);
	/* u2 cFiles - number of CFFILE entries in this cabinet: 28-29 */
	BIO_read(bio, bfb, 2);
	EVP_DigestUpdate(mdctx, bfb, 2);
	/* u2 flags: 30-31 */
	BIO_read(bio, bfb, 2);
	flags = GET_UINT16_LE(bfb);
	EVP_DigestUpdate(mdctx, bfb, 2);
	/* u2 setID must be the same for all cabinets in a set: 32-33 */
	BIO_read(bio, bfb, 2);
	EVP_DigestUpdate(mdctx, bfb, 2);
	/*
	* u2 iCabinet - number of this cabinet file in a set: 34-35
	* u2 cbCFHeader: 36-37
	* u1 cbCFFolder: 38
	* u1 cbCFData: 39
	* u22 abReserve: 40-55
	* - Additional data offset: 44-47
	* - Additional data size: 48-51
	*/
	BIO_read(bio, bfb, 22);
	/* u22 abReserve: 56-59 */
	BIO_read(bio, bfb, 4);
	EVP_DigestUpdate(mdctx, bfb, 4);

	/* TODO */
	if (flags & FLAG_PREV_CABINET) {
		/* szCabinetPrev */
		do {
			BIO_read(bio, bfb, 1);
			EVP_DigestUpdate(mdctx, bfb, 1);
		} while (bfb[0]);
		/* szDiskPrev */
		do {
			BIO_read(bio, bfb, 1);
			EVP_DigestUpdate(mdctx, bfb, 1);
		} while (bfb[0]);
	}
	if (flags & FLAG_NEXT_CABINET) {
		/* szCabinetNext */
		do {
			BIO_read(bio, bfb, 1);
			EVP_DigestUpdate(mdctx, bfb, 1);
		} while (bfb[0]);
		/* szDiskNext */
		do {
			BIO_read(bio, bfb, 1);
			EVP_DigestUpdate(mdctx, bfb, 1);
		} while (bfb[0]);
	}
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	while (nfolders) {
		BIO_read(bio, bfb, 8);
		EVP_DigestUpdate(mdctx, bfb, 8);
		nfolders--;
	}
	/* (variable) ab - the compressed data bytes */
	while (coffFiles < offset) {
		size_t want = offset - coffFiles;
		if (want > sizeof(bfb))
			want = sizeof(bfb);
		l = BIO_read(bio, bfb, want);
		if (l <= 0)
			break;
		EVP_DigestUpdate(mdctx, bfb, l);
		coffFiles += l;
	}

	EVP_DigestFinal(mdctx, mdbuf, NULL);
	EVP_MD_CTX_free(mdctx);
	BIO_free(bio);
}

static int cab_verify_pkcs7(SIGNATURE *signature, char *indata, FILE_HEADER *header,
			GLOBAL_OPTIONS *options)
{
	int ret = 1, mdok, mdtype = -1;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	unsigned char cmdbuf[EVP_MAX_MD_SIZE];
	char hexbuf[EVP_MAX_MD_SIZE*2+1];
	const EVP_MD *md;

	if (is_indirect_data_signature(signature->p7)) {
		ASN1_STRING *astr = signature->p7->d.sign->contents->d.other->value.sequence;
		const unsigned char *p = astr->data;
		SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, astr->length);
		if (idc) {
			if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
				mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
				memcpy(mdbuf, idc->messageDigest->digest->data, idc->messageDigest->digest->length);
			}
			SpcIndirectDataContent_free(idc);
		}
	}
	if (mdtype == -1) {
		printf("Failed to extract current message digest\n\n");
		goto out;
	}
	printf("Message digest algorithm  : %s\n", OBJ_nid2sn(mdtype));

	md = EVP_get_digestbynid(mdtype);
	tohex(mdbuf, hexbuf, EVP_MD_size(md));
	printf("Current message digest    : %s\n", hexbuf);

	cab_calc_digest(indata, md, cmdbuf, header->sigpos);

	tohex(cmdbuf, hexbuf, EVP_MD_size(md));
	mdok = !memcmp(mdbuf, cmdbuf, EVP_MD_size(md));
	printf("Calculated message digest : %s%s\n\n", hexbuf, mdok ? "" : "    MISMATCH!!!");
	if (!mdok) {
		printf("Signature verification: failed\n\n");
		goto out;
	}

	ret = verify_signature(signature, options);
out:
	if (!ret)
		ERR_print_errors_fp(stdout);
	return ret;
}

static PKCS7 *cab_extract_existing_pkcs7(char *indata, FILE_HEADER *header)
{
	PKCS7 *p7 = NULL;
	const unsigned char *blob;

	blob = (unsigned char*)indata + header->sigpos;
	p7 = d2i_PKCS7(NULL, &blob, header->siglen);
	return p7;
}

static int cab_verify_file(char *indata, FILE_HEADER *header, GLOBAL_OPTIONS *options)
{
	int i, ret = 1;
	PKCS7 *p7;
	STACK_OF(SIGNATURE) *signatures;
	SIGNATURE *signature = NULL;

	signatures = sk_SIGNATURE_new_null();

	if (header->header_size != 20) {
		printf("No signature found\n\n");
		goto out;
	}
	p7 = cab_extract_existing_pkcs7(indata, header);
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
		printf("Signature Index: %d %s\n", i, i==0 ? " (Primary Signature)" : "");
		signature = sk_SIGNATURE_value(signatures, i);
		ret &= cab_verify_pkcs7(signature, indata, header, options);
		if (signature->timestamp) {
			CMS_ContentInfo_free(signature->timestamp);
			ERR_clear_error();
		}
		PKCS7_free(signature->p7);
		OPENSSL_free(signature);
	}
	printf("Number of verified signatures: %d\n", i);
out:
	sk_SIGNATURE_free(signatures);
	return ret;
}

static int cab_extract_file(char *indata, FILE_HEADER *header, BIO *outdata, int output_pkcs7)
{
	int ret = 0;
	PKCS7 *sig;

	(void)BIO_reset(outdata);
	if (output_pkcs7) {
		sig = cab_extract_existing_pkcs7(indata, header);
		if (!sig) {
			printf("Unable to extract existing signature\n");
			return 1; /* FAILED */
		}
		ret = !PEM_write_bio_PKCS7(outdata, sig);
		PKCS7_free(sig);
	} else
		ret = !BIO_write(outdata, indata + header->sigpos, header->siglen);

	return ret;
}

static void cab_optional_names(size_t flags, char *indata, BIO *outdata, int *len)
{
	int i;

	i = *len;
	/* TODO */
	if (flags & FLAG_PREV_CABINET) {
		/* szCabinetPrev */
		while (GET_UINT8_LE(indata+i)) {
			BIO_write(outdata, indata+i, 1);
			i++;
		}
		BIO_write(outdata, indata+i, 1);
		i++;
		/* szDiskPrev */
		while (GET_UINT8_LE(indata+i)) {
			BIO_write(outdata, indata+i, 1);
			i++;
		}
		BIO_write(outdata, indata+i, 1);
		i++;
	}
	if (flags & FLAG_NEXT_CABINET) {
		/* szCabinetNext */
		while (GET_UINT8_LE(indata+i)) {
			BIO_write(outdata, indata+i, 1);
			i++;
		}
		BIO_write(outdata, indata+i, 1);
		i++;
		/* szDiskNext */
		while (GET_UINT8_LE(indata+i)) {
			BIO_write(outdata, indata+i, 1);
			i++;
		}
		BIO_write(outdata, indata+i, 1);
		i++;
	}
	*len = i;
}

static int cab_remove_file(char *indata, FILE_HEADER *header, size_t filesize, BIO *outdata)
{
	int i;
	unsigned short nfolders;
	size_t tmp, flags;
	static char buf[64*1024];

	/*
	 * u1 signature[4] 4643534D MSCF: 0-3
	 * u4 reserved1 00000000: 4-7
	 */
	BIO_write(outdata, indata, 8);
	/* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
	tmp = GET_UINT32_LE(indata+8) - 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(outdata, buf, 4);
	/* u4 reserved2 00000000: 12-15 */
	BIO_write(outdata, indata+12, 4);
	/* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	tmp = GET_UINT32_LE(indata+16) - 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(outdata, buf, 4);
	/*
	 * u4 reserved3 00000000: 20-23
	 * u1 versionMinor 03: 24
	 * u1 versionMajor 01: 25
	 * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
	 * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
	 */
	BIO_write(outdata, indata+20, 10);
	/* u2 flags: 30-31 */
	flags = GET_UINT16_LE(indata+30);
	PUT_UINT32_LE(flags & (FLAG_PREV_CABINET | FLAG_NEXT_CABINET), buf);
	BIO_write(outdata, buf, 2);
	/*
	 * u2 setID must be the same for all cabinets in a set: 32-33
	 * u2 iCabinet - number of this cabinet file in a set: 34-35
	 */
	BIO_write(outdata, indata+32, 4);
	i = 60;
	cab_optional_names(flags, indata, outdata, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(indata + 26);
	while (nfolders) {
		tmp = GET_UINT32_LE(indata+i);
		tmp -= 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(outdata, buf, 4);
		BIO_write(outdata, indata+i+4, 4);
		i+=8;
		nfolders--;
	}
	/* Write what's left - the compressed data bytes */
	BIO_write(outdata, indata + i, filesize - header->siglen - i);

	return 0; /* OK */
}

static void cab_modify_header(char *indata, FILE_HEADER *header, BIO *hash, BIO *outdata)
{
	int i;
	unsigned short nfolders;
	size_t flags;
	static char buf[64*1024];

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_write(hash, indata, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_write(outdata, indata+4, 4);
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
	BIO_write(hash, indata+8, 22);
	/* u2 flags: 30-31 */
	flags = GET_UINT16_LE(indata+30);
	PUT_UINT32_LE(flags, buf);
	BIO_write(hash, buf, 2);
	/* u2 setID must be the same for all cabinets in a set: 32-33 */
	BIO_write(hash, indata+32, 2);
	/*
	 * u2 iCabinet - number of this cabinet file in a set: 34-35
	 * u2 cbCFHeader: 36-37
	 * u1 cbCFFolder: 38
	 * u1 cbCFData: 39
	 * u16 abReserve: 40-55
	 * - Additional data offset: 44-47
	 * - Additional data size: 48-51
	 */
	BIO_write(outdata, indata+34, 22);
	/* u4 abReserve: 56-59 */
	BIO_write(hash, indata+56, 4);

	i = 60;
	cab_optional_names(flags, indata, hash, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(indata + 26);
	while (nfolders) {
		BIO_write(hash, indata + i, 8);
		i += 8;
		nfolders--;
	}
	/* Write what's left - the compressed data bytes */
	BIO_write(hash, indata + i, header->sigpos - i);
}

static void cab_add_header(char *indata, FILE_HEADER *header, BIO *hash, BIO *outdata)
{
	int i;
	unsigned short nfolders;
	size_t tmp, flags;
	static char buf[64*1024];
	u_char cabsigned[] = {
		0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
		0xde, 0xad, 0xbe, 0xef, /* size of cab file */
		0xde, 0xad, 0xbe, 0xef, /* size of asn1 blob */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	/* u1 signature[4] 4643534D MSCF: 0-3 */
	BIO_write(hash, indata, 4);
	/* u4 reserved1 00000000: 4-7 */
	BIO_write(outdata, indata+4, 4);
	/* u4 cbCabinet - size of this cabinet file in bytes: 8-11 */
	tmp = GET_UINT32_LE(indata+8) + 24;
	PUT_UINT32_LE(tmp, buf);
	BIO_write(hash, buf, 4);
	/* u4 reserved2 00000000: 12-15 */
	BIO_write(hash, indata+12, 4);
	/* u4 coffFiles - offset of the first CFFILE entry: 16-19 */
	tmp = GET_UINT32_LE(indata+16) + 24;
	PUT_UINT32_LE(tmp, buf+4);
	BIO_write(hash, buf+4, 4);
	/*
	 * u4 reserved3 00000000: 20-23
	 * u1 versionMinor 03: 24
	 * u1 versionMajor 01: 25
	 * u2 cFolders - number of CFFOLDER entries in this cabinet: 26-27
	 * u2 cFiles - number of CFFILE entries in this cabinet: 28-29
	 */
	memcpy(buf+4, indata+20, 10);
	flags = GET_UINT16_LE(indata+30);
	buf[4+10] = flags | FLAG_RESERVE_PRESENT;
	/* u2 setID must be the same for all cabinets in a set: 32-33 */
	memcpy(buf+16, indata+32, 2);
	BIO_write(hash, buf+4, 14);
	/* u2 iCabinet - number of this cabinet file in a set: 34-35 */
	BIO_write(outdata, indata+34, 2);
	memcpy(cabsigned+8, buf, 4);
	BIO_write(outdata, cabsigned, 20);
	BIO_write(hash, cabsigned+20, 4);

	i = 36;
	cab_optional_names(flags, indata, hash, &i);
	/*
	 * (u8 * cFolders) CFFOLDER - structure contains information about
	 * one of the folders or partial folders stored in this cabinet file
	 */
	nfolders = GET_UINT16_LE(indata + 26);
	while (nfolders) {
		tmp = GET_UINT32_LE(indata + i);
		tmp += 24;
		PUT_UINT32_LE(tmp, buf);
		BIO_write(hash, buf, 4);
		BIO_write(hash, indata + i + 4, 4);
		i += 8;
		nfolders--;
	}
	/* Write what's left - the compressed data bytes */
	BIO_write(hash, indata + i, header->fileend - i);
}

static void add_jp_attribute(PKCS7_SIGNER_INFO *si, int jp)
{
	ASN1_STRING *astr;
	int len;
	const u_char *attrs = NULL;
	static const u_char java_attrs_low[] = {
		0x30, 0x06, 0x03, 0x02, 0x00, 0x01, 0x30, 0x00
	};

	switch (jp) {
		case 0:
			attrs = java_attrs_low;
			len = sizeof(java_attrs_low);
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
		ASN1_STRING_set(astr, attrs, len);
		PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_MS_JAVA_SOMETHING),
				V_ASN1_SEQUENCE, astr);
	}
}

static void add_purpose_attribute(PKCS7_SIGNER_INFO *si, int comm)
{
	ASN1_STRING *astr;
	static u_char purpose_ind[] = {
		0x30, 0x0c,
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15
	};
	static u_char purpose_comm[] = {
		0x30, 0x0c,
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x16
	};

	astr = ASN1_STRING_new();
	if (comm) {
		ASN1_STRING_set(astr, purpose_comm, sizeof(purpose_comm));
	} else {
		ASN1_STRING_set(astr, purpose_ind, sizeof(purpose_ind));
	}
	PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_STATEMENT_TYPE_OBJID),
			V_ASN1_SEQUENCE, astr);
}

static int add_opus_attribute(PKCS7_SIGNER_INFO *si, char *desc, char *url)
{
	SpcSpOpusInfo *opus;
	ASN1_STRING *astr;
	int len;
	u_char *p = NULL;

	opus = createOpus(desc, url);
	if ((len = i2d_SpcSpOpusInfo(opus, NULL)) <= 0 || (p = OPENSSL_malloc(len)) == NULL) {
		SpcSpOpusInfo_free(opus);
		return 0; /* FAILED */
	}
	i2d_SpcSpOpusInfo(opus, &p);
	p -= len;
	astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);
	OPENSSL_free(p);

	PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_SP_OPUS_INFO_OBJID),
			V_ASN1_SEQUENCE, astr);

	SpcSpOpusInfo_free(opus);
	return 1; /* OK */
}

static PKCS7 *create_new_signature(file_type_t type,
			GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	int i, signer = -1;
	PKCS7 *sig;
	PKCS7_SIGNER_INFO *si = NULL;

	sig = PKCS7_new();
	PKCS7_set_type(sig, NID_pkcs7_signed);

	if (cparams->cert != NULL) {
		/*
		 * the private key and corresponding certificate are parsed from the PKCS12
		 * structure or loaded from the security token, so we may omit to check
		 * the consistency of a private key with the public key in an X509 certificate
		 */
		si = PKCS7_add_signature(sig, cparams->cert, cparams->pkey, options->md);
	} else {
		/* find the signer's certificate located somewhere in the whole certificate chain */
		for (i=0; i<sk_X509_num(cparams->certs); i++) {
			X509 *signcert = sk_X509_value(cparams->certs, i);
			if (X509_check_private_key(signcert, cparams->pkey)) {
				si = PKCS7_add_signature(sig, signcert, cparams->pkey, options->md);
				signer = i;
				break;
			}
		}
	}
	if (si == NULL) {
		printf("PKCS7_add_signature failed\n");
		return NULL; /* FAILED */
	}
	pkcs7_add_signing_time(si, options->signing_time);
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
		V_ASN1_OBJECT, OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1));

	if (type == FILE_TYPE_CAB && options->jp >= 0)
		add_jp_attribute(si, options->jp);

	add_purpose_attribute(si, options->comm);

	if ((options->desc || options->url) &&
			!add_opus_attribute(si, options->desc, options->url)) {
		printf("Couldn't allocate memory for opus info\n");
		return NULL; /* FAILED */
	}
	PKCS7_content_new(sig, NID_pkcs7_data);

	/* add the signer's certificate */
	if (cparams->cert != NULL)
		PKCS7_add_certificate(sig, cparams->cert);
	if (signer != -1)
		PKCS7_add_certificate(sig, sk_X509_value(cparams->certs, signer));

	/* add the certificate chain */
	for (i=0; i<sk_X509_num(cparams->certs); i++) {
		if (i == signer)
			continue;
		PKCS7_add_certificate(sig, sk_X509_value(cparams->certs, i));
	}
	/* add all cross certificates */
	if (cparams->xcerts) {
		for (i=0; i<sk_X509_num(cparams->xcerts); i++)
			PKCS7_add_certificate(sig, sk_X509_value(cparams->xcerts, i));
	}
	/* add crls */
	if (cparams->crls) {
		for (i=0; i<sk_X509_CRL_num(cparams->crls); i++)
			PKCS7_add_crl(sig, sk_X509_CRL_value(cparams->crls, i));
	}
	return sig; /* OK */
}

static int add_unauthenticated_blob(PKCS7 *sig)
{
	PKCS7_SIGNER_INFO *si;
	ASN1_STRING *astr;
	u_char *p = NULL;
	int nid, len = 1024+4;
	/* Length data for ASN1 attribute plus prefix */
	char prefix[] = "\x0c\x82\x04\x00---BEGIN_BLOB---";
	char postfix[] = "---END_BLOB---";

	si = sk_PKCS7_SIGNER_INFO_value(sig->d.sign->signer_info, 0);
	if ((p = OPENSSL_malloc(len)) == NULL)
		return 1; /* FAILED */
	memset(p, 0, len);
	memcpy(p, prefix, sizeof(prefix));
	memcpy(p+len-sizeof(postfix), postfix, sizeof(postfix));
	astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);
	nid = OBJ_create(SPC_UNAUTHENTICATED_DATA_BLOB_OBJID,
		"unauthenticatedData", "unauthenticatedData");
	PKCS7_add_attribute(si, nid, V_ASN1_SEQUENCE, astr);
	OPENSSL_free(p);
	return 0; /* OK */
}

/*
 * Append signature to the outfile
 */
#ifdef WITH_GSF
static int append_signature(PKCS7 *sig, PKCS7 *cursig, file_type_t type, cmd_type_t cmd,
			GLOBAL_OPTIONS *options, size_t *padlen, int *len, BIO *outdata, GSF_PARAMS *gsfparams)
#else
static int append_signature(PKCS7 *sig, PKCS7 *cursig, file_type_t type,
			GLOBAL_OPTIONS *options, size_t *padlen, int *len, BIO *outdata)
#endif
{
	u_char *p = NULL;
	static char buf[64*1024];
	PKCS7 *outsig = NULL;

	if (options->nest) {
		if (cursig == NULL) {
			printf("Internal error: No 'cursig' was extracted\n");
			return 1; /* FAILED */
		}
		if (pkcs7_set_nested_signature(cursig, sig, options->signing_time) == 0) {
			printf("Unable to append the nested signature to the current signature\n");
			return 1; /* FAILED */
		}
		outsig = cursig;
	} else {
		outsig = sig;
	}
	/* Append signature to outfile */
	if (((*len = i2d_PKCS7(outsig, NULL)) <= 0) || (p = OPENSSL_malloc(*len)) == NULL) {
		printf("i2d_PKCS memory allocation failed: %d\n", *len);
		return 1; /* FAILED */
	}
	i2d_PKCS7(outsig, &p);
	p -= *len;
	*padlen = (8 - *len%8) % 8;

	if (type == FILE_TYPE_PE) {
		PUT_UINT32_LE(*len + 8 + *padlen, buf);
		PUT_UINT16_LE(WIN_CERT_REVISION_2, buf + 4);
		PUT_UINT16_LE(WIN_CERT_TYPE_PKCS_SIGNED_DATA, buf + 6);
		BIO_write(outdata, buf, 8);
	}
	if (type == FILE_TYPE_PE || type == FILE_TYPE_CAB) {
		BIO_write(outdata, p, *len);
		/* pad (with 0's) asn1 blob to 8 byte boundary */
		if (*padlen > 0) {
			memset(p, 0, *padlen);
			BIO_write(outdata, p, *padlen);
		}
#ifdef WITH_GSF
	} else if (type == FILE_TYPE_MSI) {
		/* Only output signatures if we're signing */
		if (cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH) {
			if (!msi_add_DigitalSignature(gsfparams->outole, p, *len)) {
				printf("Failed to write MSI 'DigitalSignature' signature to %s\n", options->infile);
				return 1; /* FAILED */
			}
			if (gsfparams->p_msiex != NULL &&
					!msi_add_MsiDigitalSignatureEx(gsfparams->outole, gsfparams)) {
				printf("Failed to write MSI 'MsiDigitalSignatureEx' signature to %s\n", options->infile);
				return 1; /* FAILED */
			}
		}
#endif
	}
	OPENSSL_free(p);
	return 0; /* OK */
}

static void update_data_size(file_type_t type, cmd_type_t cmd, FILE_HEADER *header,
		size_t padlen, int len, BIO *outdata)
{
	static char buf[64*1024];

	if (type == FILE_TYPE_PE) {
		if (cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH) {
			/* Update signature position and size */
			(void)BIO_seek(outdata, header->header_size + 152 + header->pe32plus * 16);
			PUT_UINT32_LE(header->fileend, buf); /* Previous file end = signature table start */
			BIO_write(outdata, buf, 4);
			PUT_UINT32_LE(len+8+padlen, buf);
			BIO_write(outdata, buf, 4);
		}
		if (cmd == CMD_SIGN || cmd == CMD_REMOVE || cmd == CMD_ADD || cmd == CMD_ATTACH)
			pe_recalc_checksum(outdata, header);
	} else if (type == FILE_TYPE_CAB && (cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH)) {
		/*
		 * Update additional data size.
		 * Additional data size is located at offset 0x30 (from file beginning)
		 * and consist of 4 bytes (little-endian order).
		 */
		(void)BIO_seek(outdata, 0x30);
		PUT_UINT32_LE(len+padlen, buf);
		BIO_write(outdata, buf, 4);
	}
}

static STACK_OF(X509) *PEM_read_certs_with_pass(BIO *bin, char *certpass)
{
	STACK_OF(X509) *certs = sk_X509_new_null();
	X509 *x509;
	(void)BIO_seek(bin, 0);
	while((x509 = PEM_read_bio_X509(bin, NULL, NULL, certpass)))
		sk_X509_push(certs, x509);
	if (!sk_X509_num(certs)) {
		sk_X509_free(certs);
		return NULL;
	}
	return certs;
}

static STACK_OF(X509) *PEM_read_certs(BIO *bin, char *certpass)
{
	STACK_OF(X509) *certs = PEM_read_certs_with_pass(bin, certpass);
	if (!certs)
		certs = PEM_read_certs_with_pass(bin, NULL);
	return certs;
}


static off_t get_file_size(const char *infile)
{
	int ret;
#ifdef _WIN32
	struct _stat st;
	ret = _stat(infile, &st);
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
	return st.st_size;
}

static char *map_file(const char *infile, const off_t size)
{
	char *indata = NULL;
#ifdef WIN32
	HANDLE fh, fm;
	fh = CreateFile(infile, GENERIC_READ, FILE_SHARE_READ , NULL, OPEN_EXISTING, 0, NULL);
	if (fh == INVALID_HANDLE_VALUE)
		return NULL;
	fm = CreateFileMapping(fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (fm == NULL)
		return NULL;
	indata = MapViewOfFile(fm, FILE_MAP_READ, 0, 0, 0);
#else
	int fd = open(infile, O_RDONLY);
	if (fd < 0)
		return NULL;
	indata = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (indata == MAP_FAILED)
		return NULL;
#endif
	return indata;
}

static int input_validation(file_type_t type, GLOBAL_OPTIONS *options, FILE_HEADER *header,
			char *indata, size_t filesize)
{
	if (type == FILE_TYPE_CAB) {
		if (options->pagehash == 1)
			printf("Warning: -ph option is only valid for PE files\n");
#ifdef WITH_GSF
		if (options->add_msi_dse == 1)
			printf("Warning: -add-msi-dse option is only valid for MSI files\n");
#endif
		if (!cab_verify_header(indata, options->infile, filesize, header)) {
			printf("Corrupt CAB file\n");
			return 0; /* FAILED */
		}
	} else if (type == FILE_TYPE_PE) {
		if (options->jp >= 0)
			printf("Warning: -jp option is only valid for CAB files\n");
#ifdef WITH_GSF
		if (options->add_msi_dse == 1)
			printf("Warning: -add-msi-dse option is only valid for MSI files\n");
#endif
		if (!pe_verify_header(indata, options->infile, filesize, header)) {
			printf("Corrupt PE file\n");
			return 0; /* FAILED */
		}

	} else if (type == FILE_TYPE_MSI) {
		if (options->pagehash == 1)
			printf("Warning: -ph option is only valid for PE files\n");
		if (options->jp >= 0)
			printf("Warning: -jp option is only valid for CAB files\n");
#ifndef WITH_GSF
		printf("libgsf is not available, msi support is disabled: %s\n", options->infile);
		return 0; /* FAILED */
#endif
	}
	return 1; /* OK */
}

static int check_attached_data(file_type_t type, FILE_HEADER *header, GLOBAL_OPTIONS *options)
{
	size_t filesize;
	char *outdata;

	if (type == FILE_TYPE_PE) {
		filesize = get_file_size(options->outfile);
		if (!filesize) {
			printf("Error verifying result\n");
			return 1; /* FAILED */
		}
		outdata = map_file(options->outfile, filesize);
		if (!outdata) {
			printf("Error verifying result\n");
			return 1; /* FAILED */
		}
		if (!pe_verify_header(outdata, options->outfile, filesize, header)) {
			printf("Corrupt PE file\n");
			return 1; /* FAILED */
		}
		if (pe_verify_file(outdata, header, options)) {
			printf("Signature mismatch\n");
			return 1; /* FAILED */
		}
	} else if (type == FILE_TYPE_CAB) {
		filesize = get_file_size(options->outfile);
		if (!filesize) {
			printf("Error verifying result\n");
			return 1; /* FAILED */
		}
		outdata = map_file(options->outfile, filesize);
		if (!outdata) {
			printf("Error verifying result\n");
			return 1; /* FAILED */
		}
		if (!cab_verify_header(outdata, options->outfile, filesize, header)) {
			printf("Corrupt CAB file\n");
			return 1; /* FAILED */
		}
		if (cab_verify_file(outdata, header, options)) {
			printf("Signature mismatch\n");
			return 1; /* FAILED */
		}
	} else if (type == FILE_TYPE_MSI) {
#ifdef WITH_GSF
		GsfInput *src;
		GsfInfile *ole;
		int ret;

		src = gsf_input_stdio_new(options->outfile, NULL);
		if (!src) {
			printf("Error opening output file %s\n", options->outfile);
			return 1; /* FAILED */
		}
		ole = gsf_infile_msole_new(src, NULL);
		g_object_unref(src);

		ret = msi_verify_file(ole, options);
		g_object_unref(ole);
		if (ret) {
			printf("Signature mismatch\n");
			return 1; /* FAILED */
		}
#else
		printf("libgsf is not available, msi support is disabled: %s\n", options->infile);
		return 1; /* FAILED */
#endif
	} else {
		printf("Unknown input type for file: %s\n", options->infile);
		return 1; /* FAILED */
		}
	return 0; /* OK */
}

static int get_file_type(char *indata, char *infile, file_type_t *type)
{
	static u_char msi_signature[] = {
		0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
	};

	if (!memcmp(indata, "MSCF", 4)) {
		*type = FILE_TYPE_CAB;
	} else if (!memcmp(indata, "MZ", 2)) {
		*type = FILE_TYPE_PE;
	} else if (!memcmp(indata, msi_signature, sizeof(msi_signature))) {
		*type = FILE_TYPE_MSI;
#ifdef WITH_GSF
		gsf_init();
		gsf_initialized = 1;
#endif
	} else {
		printf("Unrecognized file type: %s\n", infile);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

#ifdef PROVIDE_ASKPASS
static char *getpassword(const char *prompt)
{
#ifdef HAVE_TERMIOS_H
	struct termios ofl, nfl;
	char *p, passbuf[1024], *pass;

	fputs(prompt, stdout);

	tcgetattr(fileno(stdin), &ofl);
	nfl = ofl;
	nfl.c_lflag &= ~ECHO;
	nfl.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &nfl) != 0) {
		printf("Failed to set terminal attributes\n");
		return NULL;
	}
	p = fgets(passbuf, sizeof(passbuf), stdin);
	if (tcsetattr(fileno(stdin), TCSANOW, &ofl) != 0)
		printf("Failed to restore terminal attributes\n");
	if (!p) {
		printf("Failed to read password\n");
		return NULL;
	}
	passbuf[strlen(passbuf)-1] = 0x00;
	pass = OPENSSL_strdup(passbuf);
	memset(passbuf, 0, sizeof(passbuf));
	return pass;
#else
	return getpass(prompt);
#endif
}
#endif

static int read_password(GLOBAL_OPTIONS *options)
{
	char passbuf[4096];
	int passfd, passlen;

	if (options->readpass) {
		passfd = open(options->readpass, O_RDONLY);
		if (passfd < 0) {
			printf("Failed to open password file: %s\n", options->readpass);
			return 0; /* FAILED */
		}
		passlen = read(passfd, passbuf, sizeof(passbuf)-1);
		close(passfd);
		if (passlen <= 0) {
			printf("Failed to read password from file: %s\n", options->readpass);
			return 0; /* FAILED */
		}
		passbuf[passlen] = 0x00;
		options->pass = OPENSSL_strdup(passbuf);
		memset(passbuf, 0, sizeof(passbuf));
#ifdef PROVIDE_ASKPASS
	} else if (options->askpass) {
		options->pass = getpassword("Password: ");
#endif
	}
	return 1; /* OK */
}

/*
 * Parse a PKCS#12 container with certificates and a private key.
 * If successful the private key will be written to cparams->pkey,
 * the corresponding certificate to cparams->cert
 * and any additional certificates to cparams->certs.
 */
static int read_pkcs12file(GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	BIO *btmp;
	PKCS12 *p12;
	int ret = 0;

	btmp = BIO_new_file(options->pkcs12file, "rb");
	if (!btmp) {
		printf("Failed to read PKCS#12 file: %s\n", options->pkcs12file);
		return 0; /* FAILED */
	}
	p12 = d2i_PKCS12_bio(btmp, NULL);
	if (!p12) {
		printf("Failed to extract PKCS#12 data: %s\n", options->pkcs12file);
		goto out; /* FAILED */
	}
	if (!PKCS12_parse(p12, options->pass ? options->pass : "", &cparams->pkey, &cparams->cert, &cparams->certs)) {
		printf("Failed to parse PKCS#12 file: %s (Wrong password?)\n", options->pkcs12file);
		PKCS12_free(p12);
		goto out; /* FAILED */
	}
	PKCS12_free(p12);
	ret = 1; /* OK */
out:
	BIO_free(btmp);
	return ret;
}

/* Obtain a copy of the whole X509_CRL chain */
STACK_OF(X509_CRL) *X509_CRL_chain_up_ref(STACK_OF(X509_CRL) *chain)
{
	STACK_OF(X509_CRL) *ret;
	int i;
	ret = sk_X509_CRL_dup(chain);
	if (ret == NULL)
		return NULL;
	for (i = 0; i < sk_X509_CRL_num(ret); i++) {
		X509_CRL *x = sk_X509_CRL_value(ret, i);
		if (!X509_CRL_up_ref(x))
			goto err;
	}
	return ret;
err:
	while (i-- > 0)
		X509_CRL_free(sk_X509_CRL_value(ret, i));
	sk_X509_CRL_free(ret);
	return NULL;
}

/*
 * Load certificates from a file.
 * If successful all certificates will be written to cparams->certs
 * and optional CRLs will be written to cparams->crls.
 */
static int read_certfile(GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	BIO *btmp;
	int ret = 0;

	btmp = BIO_new_file(options->certfile, "rb");
	if (!btmp) {
		printf("Failed to read certificate file: %s\n", options->certfile);
		return 0; /* FAILED */
	}
	/* .pem certificate file */
	cparams->certs = PEM_read_certs(btmp, "");

	/* .der certificate file */
	if (!cparams->certs) {
		X509 *x = NULL;
		(void)BIO_seek(btmp, 0);
		if (d2i_X509_bio(btmp, &x)) {
			cparams->certs = sk_X509_new_null();
			if (!sk_X509_push(cparams->certs, x)) {
				X509_free(x);
				goto out; /* FAILED */
			}
			printf("Warning: The certificate file contains a single x509 certificate\n");
		}
	}

	/* .spc or .p7b certificate file (PKCS#7 structure) */
	if (!cparams->certs) {
		PKCS7 *p7;
		(void)BIO_seek(btmp, 0);
		p7 = d2i_PKCS7_bio(btmp, NULL);
		if (!p7)
			goto out; /* FAILED */
		cparams->certs = X509_chain_up_ref(p7->d.sign->cert);

		/* additional CRLs may be supplied as part of a PKCS#7 signed data structure */
		cparams->crls = X509_CRL_chain_up_ref(p7->d.sign->crl);
		PKCS7_free(p7);
	}

	ret = 1; /* OK */
out:
	if (ret == 0)
		printf("No certificate found\n");
	BIO_free(btmp);
	return ret;
}

/* Load additional (cross) certificates from a .pem file */
static int read_xcertfile(GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	BIO *btmp;
	PKCS7 *p7;
	int ret = 0;

	btmp = BIO_new_file(options->xcertfile, "rb");
	if (!btmp) {
		printf("Failed to read cross certificates file: %s\n", options->xcertfile);
		return 0; /* FAILED */
	}
	cparams->xcerts = PEM_read_certs(btmp, "");
	if (!cparams->xcerts) {
		printf("Failed to read cross certificates file: %s\n", options->xcertfile);
		goto out; /* FAILED */
	}

	ret = 1; /* OK */
out:
	BIO_free(btmp);
	return ret;
}

/* Load the private key from a file */
static int read_keyfile(GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	BIO *btmp;
	int ret = 0;

	btmp = BIO_new_file(options->keyfile, "rb");
	if (!btmp) {
		printf("Failed to read private key file: %s\n", options->keyfile);
		return 0; /* FAILED */
	}
	if (((cparams->pkey = d2i_PrivateKey_bio(btmp, NULL)) == NULL &&
			(BIO_seek(btmp, 0) == 0) &&
			(cparams->pkey = PEM_read_bio_PrivateKey(btmp, NULL, NULL, options->pass ? options->pass : "")) == NULL &&
			(BIO_seek(btmp, 0) == 0) &&
			(cparams->pkey = PEM_read_bio_PrivateKey(btmp, NULL, NULL, NULL)) == NULL)) {
		printf("Failed to decode private key file: %s (Wrong password?)\n", options->keyfile);
		goto out; /* FAILED */
	}
	ret = 1; /* OK */
out:
	BIO_free(btmp);
	return ret;
}

/*
 * Decode Microsoft Private Key (PVK) file.
 * PVK is a proprietary Microsoft format that stores a cryptographic private key.
 * PVK files are often password-protected.
 * A PVK file may have an associated .spc (PKCS7) certificate file.
 */
static char *find_pvk_key(GLOBAL_OPTIONS *options)
{
	unsigned char magic[4];
	/* Microsoft Private Key format Header Hexdump */
	unsigned char pvkhdr[4] = { 0x1e, 0xf1, 0xb5, 0xb0 };
	char *pvkfile = NULL;
	BIO *btmp;

	if (!options->keyfile
#ifndef OPENSSL_NO_ENGINE
			|| options->p11module
#endif /* OPENSSL_NO_ENGINE */
			)
		return NULL; /* FAILED */
	btmp = BIO_new_file(options->keyfile, "rb");
	if (!btmp)
		return NULL; /* FAILED */
	magic[0] = 0x00;
	BIO_read(btmp, magic, 4);
	if (!memcmp(magic, pvkhdr, 4)) {
		pvkfile = options->keyfile;
		options->keyfile = NULL;
	}
	BIO_free(btmp);
	return pvkfile;
}

static int read_pvk_key(GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	BIO *btmp;
	int ret = 0;

	btmp = BIO_new_file(options->pvkfile, "rb");
	if (!btmp) {
		printf("Failed to read private key file: %s\n", options->pvkfile);
		return 0; /* FAILED */
	}
	if (((cparams->pkey = b2i_PVK_bio(btmp, NULL, options->pass ? options->pass : "")) == NULL &&
			(BIO_seek(btmp, 0) == 0) &&
			(cparams->pkey = b2i_PVK_bio(btmp, NULL, NULL)) == NULL)) {
		printf("Failed to decode private key file: %s\n", options->pvkfile);
		goto out; /* FAILED */
	}
	ret = 1; /* OK */
out:
	BIO_free(btmp);
	return ret;
}

#ifndef OPENSSL_NO_ENGINE

/* Load an engine in a shareable library */
ENGINE *dynamic_engine(GLOBAL_OPTIONS *options)
{
	ENGINE *engine = ENGINE_by_id("dynamic");
	if (!engine) {
		printf("Failed to load 'dynamic' engine\n");
		return NULL; /* FAILED */
	}
	if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", options->p11engine, 0)
			|| !ENGINE_ctrl_cmd_string(engine, "ID", "pkcs11", 0)
			|| !ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "1", 0)
			|| !ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0)) {
		printf("Failed to set 'dynamic' engine\n");
		ENGINE_free(engine);
		return NULL; /* FAILED */
	}
	return engine; /* OK */
}

/* Load a pkcs11 engine */
ENGINE *pkcs11_engine(GLOBAL_OPTIONS *options)
{
	ENGINE *engine = ENGINE_by_id("pkcs11");
	if (!engine) {
		printf("Failed to find and load 'pkcs11' engine\n");
		return NULL; /* FAILED */
	}
	return engine; /* OK */
}

/* Load the private key and the signer certificate from a security token */
static int read_token(GLOBAL_OPTIONS *options, ENGINE *engine, CRYPTO_PARAMS *cparams)
{
	if (!ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", options->p11module, 0)) {
		printf("Failed to set pkcs11 engine MODULE_PATH to '%s'\n", options->p11module);
		ENGINE_free(engine);
		return 0; /* FAILED */
	}
	if (options->pass != NULL && !ENGINE_ctrl_cmd_string(engine, "PIN", options->pass, 0)) {
		printf("Failed to set pkcs11 PIN\n");
		ENGINE_free(engine);
		return 0; /* FAILED */
	}
	if (!ENGINE_init(engine)) {
		printf("Failed to initialized pkcs11 engine\n");
		ENGINE_free(engine);
		return 0; /* FAILED */
	}
	/*
	 * ENGINE_init() returned a functional reference, so free the structural
	 * reference from ENGINE_by_id().
	 */
	ENGINE_free(engine);

	if (options->p11cert) {
		struct {
			const char *id;
			X509 *cert;
		} parms;

		parms.id = options->p11cert;
		parms.cert = NULL;
		ENGINE_ctrl_cmd(engine, "LOAD_CERT_CTRL", 0, &parms, NULL, 1);
		if (!parms.cert) {
			printf("Failed to load certificate %s\n", options->p11cert);
			ENGINE_finish(engine);
			return 0; /* FAILED */
		} else
			cparams->cert = parms.cert;
	}

	cparams->pkey = ENGINE_load_private_key(engine, options->keyfile, NULL, NULL);
	/* Free the functional reference from ENGINE_init */
	ENGINE_finish(engine);
	if (!cparams->pkey) {
		printf("Failed to load private key %s\n", options->keyfile);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}
#endif /* OPENSSL_NO_ENGINE */

static int read_crypto_params(GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams)
{
	int ret = 0;

	/* Microsoft Private Key format support */
	options->pvkfile = find_pvk_key(options);
	if (options->pvkfile) {
		if (!read_certfile(options, cparams) || !read_pvk_key(options, cparams))
			goto out; /* FAILED */

	/* PKCS#12 container with certificates and the private key ("-pkcs12" option) */
	} else if (options->pkcs12file) {
		if (!read_pkcs12file(options, cparams))
			goto out; /* FAILED */

#ifndef OPENSSL_NO_ENGINE
	/* PKCS11 engine and module support */
	} else if (options->p11module) {
		ENGINE *engine;
		if (options->p11engine)
			engine = dynamic_engine(options);
		else
			engine = pkcs11_engine(options);
		if (!engine)
			goto out; /* FAILED */
		printf("Engine \"%s\" set.\n", ENGINE_get_id(engine));

		/* Load the private key and the signer certificate from the security token*/
		if (!read_token(options, engine, cparams))
			goto out; /* FAILED */

		/* Load the signer certificate and the whole certificate chain from a file */
		if (options->certfile && !read_certfile(options, cparams))
			goto out; /* FAILED */

	/* PEM / DER / SPC file format support */
	} else if (!read_certfile(options, cparams) || !read_keyfile(options, cparams))
		goto out; /* FAILED */
#endif /* OPENSSL_NO_ENGINE */

	/* Load additional (cross) certificates ("-ac" option) */
	if (options->xcertfile && !read_xcertfile(options, cparams))
		goto out; /* FAILED */

	ret = 1;
out:
	/* reset password */
	if (options->pass) {
		memset(options->pass, 0, strlen(options->pass));
		OPENSSL_free(options->pass);
	}
	return ret; /* OK */
}

static void free_crypto_params(CRYPTO_PARAMS *cparams)
{
	/* If key is NULL nothing is done */
	EVP_PKEY_free(cparams->pkey);
	cparams->pkey = NULL;
	/* If X509 structure is NULL nothing is done */
	X509_free(cparams->cert);
	cparams->cert = NULL;
	/* Free up all elements of sk structure and sk itself */
	sk_X509_pop_free(cparams->certs, X509_free);
	cparams->certs = NULL;
	sk_X509_pop_free(cparams->xcerts, X509_free);
	cparams->xcerts = NULL;
	sk_X509_CRL_pop_free(cparams->crls, X509_CRL_free);
	cparams->crls = NULL;
}

static void free_options(GLOBAL_OPTIONS *options)
{
	/* If memory has not been allocated nothing is done */
	OPENSSL_free(options->cafile);
	OPENSSL_free(options->untrusted);
	OPENSSL_free(options->crlfile);
	OPENSSL_free(options->crluntrusted);
}

static char *get_cafile(void)
{
	const char *sslpart1, *sslpart2;
	char *cafile, *openssl_dir, *str_begin, *str_end;

#ifdef CA_BUNDLE_PATH
	if (strcmp(CA_BUNDLE_PATH, ""))
		return OPENSSL_strdup(CA_BUNDLE_PATH);
#endif
	sslpart1 = OpenSSL_version(OPENSSL_DIR);
	sslpart2 = "/certs/ca-bundle.crt";
	str_begin = strchr(sslpart1, '"');
	str_end = strrchr(sslpart1, '"');
	if (str_begin && str_end && str_begin < str_end) {
		openssl_dir = OPENSSL_strndup(str_begin + 1, str_end - str_begin - 1);
	} else {
		openssl_dir = OPENSSL_strdup("/etc");
	}
	cafile = OPENSSL_malloc(strlen(sslpart1) + strlen(sslpart2) + 1);
	strcpy(cafile, openssl_dir);
	strcat(cafile, sslpart2);

	OPENSSL_free(openssl_dir);
	return cafile;
}

static PKCS7 *get_sigfile(char *sigfile, file_type_t type)
{
	PKCS7 *sig = NULL;
	size_t sigfilesize;
	char *insigdata;
	FILE_HEADER header;
	BIO *sigbio;
	const char pemhdr[] = "-----BEGIN PKCS7-----";

	sigfilesize = get_file_size(sigfile);
	if (!sigfilesize) {
		return NULL; /* FAILED */
	}
	insigdata = map_file(sigfile, sigfilesize);
	if (!insigdata) {
		printf("Failed to open file: %s\n", sigfile);
		return NULL; /* FAILED */
	}
	if (sigfilesize >= sizeof(pemhdr) && !memcmp(insigdata, pemhdr, sizeof(pemhdr)-1)) {
		sigbio = BIO_new_mem_buf(insigdata, sigfilesize);
		sig = PEM_read_bio_PKCS7(sigbio, NULL, NULL, NULL);
		BIO_free_all(sigbio);
	} else {
		/* reset header */
		memset(&header, 0, sizeof(FILE_HEADER));
		header.siglen = sigfilesize;
		header.sigpos = 0;
		if (type == FILE_TYPE_PE)
			sig = pe_extract_existing_pkcs7(insigdata, &header);
		else if (type == FILE_TYPE_CAB)
			sig = cab_extract_existing_pkcs7(insigdata, &header);
		else if (type == FILE_TYPE_MSI) {
#ifdef WITH_GSF
			const unsigned char *p = (unsigned char*)insigdata;
			sig = d2i_PKCS7(NULL, &p, sigfilesize);
#else
			printf("libgsf is not available, msi support is disabled\n");
			return NULL; /* FAILED */
#endif
		}
	}
	return sig; /* OK */
}

/*
 * Obtain an existing signature or create a new one
 */
static PKCS7 *get_pkcs7(cmd_type_t cmd, BIO *hash, file_type_t type, char *indata,
			GLOBAL_OPTIONS *options, FILE_HEADER *header, CRYPTO_PARAMS *cparams)
{
	PKCS7 *sig = NULL;

	if (cmd == CMD_ATTACH) {
		sig = get_sigfile(options->sigfile, type);
		if (!sig) {
			printf("Unable to extract valid signature\n");
			return NULL; /* FAILED */
		}
	} else if (cmd == CMD_SIGN) {
		sig = create_new_signature(type, options, cparams);
		if (!sig) {
			printf("Creating a new signature failed\n");
			return NULL; /* FAILED */
		}
		if (!set_indirect_data_blob(sig, hash, type, indata, options, header)) {
			printf("Signing failed\n");
			return NULL; /* FAILED */
		}
	}
	return sig;
}

/*
 * Prepare the output file for signing
 */
#ifdef WITH_GSF


static PKCS7 *msi_presign_file(file_type_t type, cmd_type_t cmd, FILE_HEADER *header,
			GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams, char *indata,
			BIO *hash, GsfInfile *ole, GSF_PARAMS *gsfparams, PKCS7 **cursig)
{
	PKCS7 *sig = NULL;

	/* Create outdata MSI file */
	if (!access(options->outfile, R_OK)) {
		/* outdata file exists */
		printf("Failed to create file: %s\n", options->outfile);
		return NULL; /* FAILED */
	}
	gsfparams->sink = gsf_output_stdio_new(options->outfile, NULL);
	if (!gsfparams->sink) {
		printf("Failed to create file: %s\n", options->outfile);
		return NULL; /* FAILED */
	}
	gsfparams->outole = gsf_outfile_msole_new(gsfparams->sink);

	BIO_push(hash, BIO_new(BIO_s_null()));
	if (options->add_msi_dse && !msi_calc_MsiDigitalSignatureEx(ole, options->md, hash, gsfparams))
		return NULL; /* FAILED */
	if (!msi_handle_dir(ole, gsfparams->outole, hash)) {
		printf("Unable to msi_handle_dir()\n");
		return NULL; /* FAILED */
	}

	/* Obtain a current signature from previously-signed file */
	if ((cmd == CMD_SIGN && options->nest) ||
			(cmd == CMD_ATTACH && options->nest) || cmd == CMD_ADD) {
		if (!msi_check_MsiDigitalSignatureEx(ole, options->md))
			return NULL; /* FAILED */
		*cursig = msi_extract_signature_to_pkcs7(ole);
		if (*cursig == NULL) {
			printf("Unable to extract existing signature in -nest mode\n");
			return NULL; /* FAILED */
		}
		if (cmd == CMD_ADD)
			sig = *cursig;
	}

	/* Obtain an existing signature or create a new one */
	if ((cmd == CMD_ATTACH) || (cmd == CMD_SIGN))
		sig = get_pkcs7(cmd, hash, type, indata, options, header, cparams);
	return sig; /* OK */
}
#endif

static PKCS7 *pe_presign_file(file_type_t type, cmd_type_t cmd, FILE_HEADER *header,
			GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams, char *indata,
			BIO *hash, BIO *outdata, PKCS7 **cursig)
{
	PKCS7 *sig = NULL;

	/* Obtain a current signature from previously-signed file */
	if ((cmd == CMD_SIGN && options->nest) ||
			(cmd == CMD_ATTACH && options->nest) || cmd == CMD_ADD) {
		*cursig = pe_extract_existing_pkcs7(indata, header);
		if (!*cursig) {
			printf("Unable to extract existing signature\n");
			return NULL; /* FAILED */
		}
		if (cmd == CMD_ADD)
			sig = *cursig;
	}
	if (header->sigpos > 0) {
		/* Strip current signature */
		header->fileend = header->sigpos;
	}
	pe_modify_header(indata, header, hash, outdata);
	/* Obtain an existing signature or create a new one */
	if ((cmd == CMD_ATTACH) || (cmd == CMD_SIGN))
		sig = get_pkcs7(cmd, hash, type, indata, options, header, cparams);
	return sig; /* OK */
}

static PKCS7 *cab_presign_file(file_type_t type, cmd_type_t cmd, FILE_HEADER *header,
			GLOBAL_OPTIONS *options, CRYPTO_PARAMS *cparams, char *indata,
			BIO *hash, BIO *outdata, PKCS7 **cursig)
{
	PKCS7 *sig = NULL;

	/* Obtain a current signature from previously-signed file */
	if ((cmd == CMD_SIGN && options->nest) ||
			(cmd == CMD_ATTACH && options->nest) || cmd == CMD_ADD) {
		*cursig = cab_extract_existing_pkcs7(indata, header);
		if (!*cursig) {
			printf("Unable to extract existing signature\n");
			return NULL; /* FAILED */
		}
		if (cmd == CMD_ADD)
			sig = *cursig;
	}
	if (header->header_size == 20)
		/* Strip current signature and modify header */
		cab_modify_header(indata, header, hash, outdata);
	else
		cab_add_header(indata, header, hash, outdata);
	/* Obtain an existing signature or create a new one */
	if ((cmd == CMD_ATTACH) || (cmd == CMD_SIGN))
		sig = get_pkcs7(cmd, hash, type, indata, options, header, cparams);
	return sig; /* OK */
}

static void print_version()
{
	printf(PACKAGE_STRING ", using:\n\t%s (Library: %s)\n\t%s\n",
		OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION),
#ifdef ENABLE_CURL
		curl_version()
#else
		"no libcurl available"
#endif /* ENABLE_CURL */
		);
	printf(
#ifdef WITH_GSF
		"\tlibgsf %d.%d.%d\n",
		libgsf_major_version,
		libgsf_minor_version,
		libgsf_micro_version
#else
		"\tno libgsf available\n"
#endif /* WITH_GSF */
		);
	printf("\nPlease send bug-reports to " PACKAGE_BUGREPORT "\n\n");
}

static cmd_type_t get_command(char **argv)
{
	if (!strcmp(argv[1], "--help")) {
		print_version();
		help_for(argv[0], "all");
	} else if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
		print_version();
		exit(-1);
	} else if (!strcmp(argv[1], "sign"))
		return CMD_SIGN;
	else if (!strcmp(argv[1], "extract-signature"))
		return CMD_EXTRACT;
	else if (!strcmp(argv[1], "attach-signature"))
		return CMD_ATTACH;
	else if (!strcmp(argv[1], "remove-signature"))
		return CMD_REMOVE;
	else if (!strcmp(argv[1], "verify"))
		return CMD_VERIFY;
	else if (!strcmp(argv[1], "add"))
		return CMD_ADD;
	return CMD_SIGN;
}

static int main_configure(int argc, char **argv, cmd_type_t *cmd, GLOBAL_OPTIONS *options)
{
	int i;
	char *failarg = NULL;
	const char *argv0;

	argv0 = argv[0];
	if (argc > 1) {
		*cmd = get_command(argv);
		argv++;
		argc--;
	}
	/* reset options */
	memset(options, 0, sizeof(GLOBAL_OPTIONS));
	options->md = EVP_sha1();
	options->signing_time = INVALID_TIME;
	options->jp = -1;

	if (*cmd == CMD_VERIFY || *cmd == CMD_ATTACH) {
		options->cafile = get_cafile();
		options->untrusted = get_cafile();
	}
	for (argc--,argv++; argc >= 1; argc--,argv++) {
		if (!strcmp(*argv, "-in")) {
			if (--argc < 1) usage(argv0, "all");
			options->infile = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) usage(argv0, "all");
			options->outfile = *(++argv);
		} else if (!strcmp(*argv, "-sigin")) {
			if (--argc < 1) usage(argv0, "all");
			options->sigfile = *(++argv);
		} else if ((*cmd == CMD_SIGN) && (!strcmp(*argv, "-spc") || !strcmp(*argv, "-certs"))) {
			if (--argc < 1) usage(argv0, "all");
			options->certfile = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-ac")) {
			if (--argc < 1) usage(argv0, "all");
			options->xcertfile = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-key")) {
			if (--argc < 1) usage(argv0, "all");
			options->keyfile = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs12")) {
			if (--argc < 1) usage(argv0, "all");
			options->pkcs12file = *(++argv);
		} else if ((*cmd == CMD_EXTRACT) && !strcmp(*argv, "-pem")) {
			options->output_pkcs7 = 1;
#ifndef OPENSSL_NO_ENGINE
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11cert")) {
			if (--argc < 1) usage(argv0, "all");
			options->p11cert = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11engine")) {
			if (--argc < 1) usage(argv0, "all");
			options->p11engine = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11module")) {
			if (--argc < 1) usage(argv0, "all");
			options->p11module = *(++argv);
#endif /* OPENSSL_NO_ENGINE */
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-pass")) {
			if (options->askpass || options->readpass) usage(argv0, "all");
			if (--argc < 1) usage(argv0, "all");
			options->pass = OPENSSL_strdup(*(++argv));
			memset(*argv, 0, strlen(*argv));
#ifdef PROVIDE_ASKPASS
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-askpass")) {
			if (options->pass || options->readpass) usage(argv0, "all");
			options->askpass = 1;
#endif
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-readpass")) {
			if (options->askpass || options->pass) usage(argv0, "all");
			if (--argc < 1) usage(argv0, "all");
			options->readpass = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-comm")) {
			options->comm = 1;
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-ph")) {
			options->pagehash = 1;
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-n")) {
			if (--argc < 1) usage(argv0, "all");
			options->desc = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-h")) {
			if (--argc < 1) usage(argv0, "all");
			++argv;
			if (!strcmp(*argv, "md5")) {
				options->md = EVP_md5();
			} else if (!strcmp(*argv, "sha1")) {
				options->md = EVP_sha1();
			} else if (!strcmp(*argv, "sha2") || !strcmp(*argv, "sha256")) {
				options->md = EVP_sha256();
			} else if (!strcmp(*argv, "sha384")) {
				options->md = EVP_sha384();
			} else if (!strcmp(*argv, "sha512")) {
				options->md = EVP_sha512();
			} else {
				usage(argv0, "all");
			}
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-i")) {
			if (--argc < 1) usage(argv0, "all");
			options->url = *(++argv);
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-st")) {
			if (--argc < 1) usage(argv0, "all");
			options->signing_time = (time_t)strtoul(*(++argv), NULL, 10);
#ifdef ENABLE_CURL
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ADD) && !strcmp(*argv, "-t")) {
			if (--argc < 1) usage(argv0, "all");
			options->turl[options->nturl++] = *(++argv);
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ADD) && !strcmp(*argv, "-ts")) {
			if (--argc < 1) usage(argv0, "all");
			options->tsurl[options->ntsurl++] = *(++argv);
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ADD) && !strcmp(*argv, "-p")) {
			if (--argc < 1) usage(argv0, "all");
			options->proxy = *(++argv);
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ADD) && !strcmp(*argv, "-noverifypeer")) {
			options->noverifypeer = 1;
#endif
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ADD) && !strcmp(*argv, "-addUnauthenticatedBlob")) {
			options->addBlob = 1;
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ATTACH) && !strcmp(*argv, "-nest")) {
			options->nest = 1;
		} else if ((*cmd == CMD_VERIFY) && !strcmp(*argv, "-timestamp-expiration")) {
			options->timestamp_expiration = 1;
		} else if ((*cmd == CMD_SIGN || *cmd == CMD_ADD || *cmd == CMD_VERIFY) && !strcmp(*argv, "-verbose")) {
			options->verbose = 1;
#ifdef WITH_GSF
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "-add-msi-dse")) {
			options->add_msi_dse = 1;
#endif
		} else if ((*cmd == CMD_VERIFY || *cmd == CMD_ATTACH) && !strcmp(*argv, "-CAfile")) {
			if (--argc < 1) usage(argv0, "all");
			OPENSSL_free(options->cafile);
			options->cafile = OPENSSL_strdup(*++argv);
		} else if ((*cmd == CMD_VERIFY || *cmd == CMD_ATTACH) && !strcmp(*argv, "-CRLfile")) {
			if (--argc < 1) usage(argv0, "all");
			options->crlfile = OPENSSL_strdup(*++argv);
		} else if ((*cmd == CMD_VERIFY || *cmd == CMD_ATTACH) && !strcmp(*argv, "-CRLuntrusted")) {
			if (--argc < 1) usage(argv0, "all");
			options->crluntrusted = OPENSSL_strdup(*++argv);
		} else if ((*cmd == CMD_VERIFY || *cmd == CMD_ATTACH) && !strcmp(*argv, "-untrusted")) {
			if (--argc < 1) usage(argv0, "all");
			OPENSSL_free(options->untrusted);
			options->untrusted = OPENSSL_strdup(*++argv);
		} else if ((*cmd == CMD_VERIFY) && !strcmp(*argv, "-require-leaf-hash")) {
			if (--argc < 1) usage(argv0, "all");
			options->leafhash = (*++argv);
		} else if ((*cmd == CMD_ADD) && !strcmp(*argv, "--help")) {
			help_for(argv0, "add");
		} else if ((*cmd == CMD_ATTACH) && !strcmp(*argv, "--help")) {
			help_for(argv0, "attach-signature");
		} else if ((*cmd == CMD_EXTRACT) && !strcmp(*argv, "--help")) {
			help_for(argv0, "extract-signature");
		} else if ((*cmd == CMD_REMOVE) && !strcmp(*argv, "--help")) {
			help_for(argv0, "remove-signature");
		} else if ((*cmd == CMD_SIGN) && !strcmp(*argv, "--help")) {
			help_for(argv0, "sign");
		} else if ((*cmd == CMD_VERIFY) && !strcmp(*argv, "--help")) {
			help_for(argv0, "verify");
		} else if (!strcmp(*argv, "-jp")) {
			char *ap;
			if (--argc < 1) usage(argv0, "all");
			ap = *(++argv);
			for (i=0; ap[i]; i++) ap[i] = tolower((int)ap[i]);
			if (!strcmp(ap, "low")) {
				options->jp = 0;
			} else if (!strcmp(ap, "medium")) {
				options->jp = 1;
			} else if (!strcmp(ap, "high")) {
				options->jp = 2;
			}
			if (options->jp != 0) usage(argv0, "all"); /* XXX */
		} else {
			failarg = *argv;
			break;
		}
	}
	if (!options->infile && argc > 0) {
		options->infile = *(argv++);
		argc--;
	}
	if (*cmd != CMD_VERIFY && (!options->outfile && argc > 0)) {
		if (!strcmp(*argv, "-out")) {
			argv++;
			argc--;
		}
		if (argc > 0) {
			options->outfile = *(argv++);
			argc--;
		}
	}
	if (argc > 0 ||
#ifdef ENABLE_CURL
		(options->nturl && options->ntsurl) ||
#endif
		!options->infile ||
		(*cmd != CMD_VERIFY && !options->outfile) ||
		(*cmd == CMD_SIGN && !((options->certfile && options->keyfile) ||
#ifndef OPENSSL_NO_ENGINE
			options->p11module ||
#endif /* OPENSSL_NO_ENGINE */
			options->pkcs12file))) {
		if (failarg)
			printf("Unknown option: %s\n", failarg);
		usage(argv0, "all");
	}

	if ((*cmd == CMD_VERIFY || *cmd == CMD_ATTACH) && access(options->cafile, R_OK)) {
		printf("Use the \"-CAfile\" option to add one or more trusted CA certificates to verify the signature.\n");
		return 0; /* FAILED */
	}

	return 1;
}

int main(int argc, char **argv)
{
	GLOBAL_OPTIONS options;
	FILE_HEADER header;
	CRYPTO_PARAMS cparams;
#ifdef WITH_GSF
	GSF_PARAMS gsfparams;
#endif
	BIO *hash = NULL, *outdata = NULL;
	PKCS7 *cursig = NULL, *sig = NULL;
	char *indata = NULL;
	int ret = -1, len = 0;
	size_t padlen = 0, filesize = 0;
	file_type_t type;
	cmd_type_t cmd = CMD_SIGN;

	/* Set up OpenSSL */
	if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
			| OPENSSL_INIT_ADD_ALL_CIPHERS
			| OPENSSL_INIT_ADD_ALL_DIGESTS
			| OPENSSL_INIT_LOAD_CONFIG, NULL))
		DO_EXIT_0("Failed to init crypto\n");

	/* create some MS Authenticode OIDS we need later on */
	if (!OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL) ||
			!OBJ_create(SPC_MS_JAVA_SOMETHING, NULL, NULL) ||
			!OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL) ||
			!OBJ_create(SPC_NESTED_SIGNATURE_OBJID, NULL, NULL))
		DO_EXIT_0("Failed to create objects\n");

	/* reset crypto */
	memset(&cparams, 0, sizeof(CRYPTO_PARAMS));

	/* commands and options initialization */
	if (!main_configure(argc, argv, &cmd, &options))
		goto err_cleanup;
	if (!read_password(&options))
		goto err_cleanup;

	/* read key and certificates */
	if (cmd == CMD_SIGN && !read_crypto_params(&options, &cparams))
		goto err_cleanup;

	/* check if indata is cab or pe */
	filesize = get_file_size(options.infile);
	if (filesize == 0)
		goto err_cleanup;
	indata = map_file(options.infile, filesize);
	if (indata == NULL)
		DO_EXIT_1("Failed to open file: %s\n", options.infile);

	/* reset file header */
	memset(&header, 0, sizeof(FILE_HEADER));
	header.fileend = filesize;
#ifdef WITH_GSF
	/* reset Gsf parameters */
	memset(&gsfparams, 0, sizeof(GSF_PARAMS));
#endif /* WITH_GSF */

	if (!get_file_type(indata, options.infile, &type))
		goto err_cleanup;

	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, options.md);

	if (!input_validation(type, &options, &header, indata, filesize))
		goto err_cleanup;

#ifdef WITH_GSF
	if (type == FILE_TYPE_MSI) {
		GsfInput *src;
		GsfInfile *ole;

		src = gsf_input_stdio_new(options.infile, NULL);
		if (!src)
			DO_EXIT_1("Error opening file %s\n", options.infile);
		ole = gsf_infile_msole_new(src, NULL);
		g_object_unref(src);

		if (cmd == CMD_EXTRACT) {
			ret = msi_extract_file(ole, &options);
			g_object_unref(ole);
			goto skip_signing;
		} else if (cmd == CMD_VERIFY) {
			ret = msi_verify_file(ole, &options);
			g_object_unref(ole);
			goto skip_signing;
		} else {
			sig = msi_presign_file(type, cmd, &header, &options, &cparams, indata,
				hash, ole, &gsfparams, &cursig);
			if (cmd == CMD_REMOVE) {
				g_object_unref(ole);
				if (gsfparams.outole) {
					gsf_output_close(GSF_OUTPUT(gsfparams.outole));
					g_object_unref(gsfparams.outole);
					g_object_unref(gsfparams.sink);
					ret = 0;
					goto skip_signing;
				} else
					/* Failed to create output file */
					goto err_cleanup;
			} else if (!sig) {
				PKCS7_free(cursig);
				OPENSSL_free(gsfparams.p_msiex);
				g_object_unref(ole);
				goto err_cleanup;
			}
		}
		g_object_unref(ole);
	}
#endif /* WITH_GSF */

	if ((type == FILE_TYPE_CAB || type == FILE_TYPE_PE) && (cmd != CMD_VERIFY)) {
		/* Create outdata file */
#ifdef WIN32
		if (!access(options.outfile, R_OK))
			/* outdata file exists */
			DO_EXIT_1("Failed to create file: %s\n", options.outfile);
#endif
		outdata = BIO_new_file(options.outfile, FILE_CREATE_MODE);
		if (outdata == NULL)
			DO_EXIT_1("Failed to create file: %s\n", options.outfile);
		BIO_push(hash, outdata);
	}

	if (type == FILE_TYPE_CAB) {
		if (!(header.flags & FLAG_RESERVE_PRESENT) &&
				(cmd == CMD_REMOVE || cmd == CMD_EXTRACT)) {
			DO_EXIT_1("CAB file does not have any signature: %s\n", options.infile);
		} else if (cmd == CMD_EXTRACT) {
			ret = cab_extract_file(indata, &header, outdata, options.output_pkcs7);
			goto skip_signing;
		} else if (cmd == CMD_REMOVE) {
			ret = cab_remove_file(indata, &header, filesize, outdata);
			goto skip_signing;
		} else if (cmd == CMD_VERIFY) {
			ret = cab_verify_file(indata, &header, &options);
			goto skip_signing;
		} else {
			sig = cab_presign_file(type, cmd, &header, &options, &cparams, indata,
				hash, outdata, &cursig);
			if (!sig)
				goto err_cleanup;
		}
	} else if (type == FILE_TYPE_PE) {
		if ((cmd == CMD_REMOVE || cmd == CMD_EXTRACT) && header.sigpos == 0) {
			DO_EXIT_1("PE file does not have any signature: %s\n", options.infile);
		} else if (cmd == CMD_EXTRACT) {
			ret = pe_extract_file(indata, &header, outdata, options.output_pkcs7);
			goto skip_signing;
		} else if (cmd == CMD_VERIFY) {
			ret = pe_verify_file(indata, &header, &options);
			goto skip_signing;
		} else {
			sig = pe_presign_file(type, cmd, &header, &options, &cparams, indata,
				hash, outdata, &cursig);
			if (cmd == CMD_REMOVE) {
				ret = 0; /* OK */
				goto skip_signing;
			} else if (!sig)
				goto err_cleanup;
		}
	}

#ifdef ENABLE_CURL
	/* add counter-signature/timestamp */
	if (options.nturl && add_timestamp_authenticode(sig, &options))
		DO_EXIT_0("Authenticode timestamping failed\n");
	if (options.ntsurl && add_timestamp_rfc3161(sig, &options))
		DO_EXIT_0("RFC 3161 timestamping failed\n");
#endif /* ENABLE_CURL */

	if (options.addBlob && add_unauthenticated_blob(sig))
		DO_EXIT_0("Adding unauthenticated blob failed\n");

#if 0
	if (!PEM_write_PKCS7(stdout, sig))
		DO_EXIT_0("PKCS7 output failed\n");
#endif

#ifdef WITH_GSF
	ret = append_signature(sig, cursig, type, cmd, &options, &padlen, &len,
			outdata, &gsfparams);
	if (type == FILE_TYPE_MSI) {
		gsf_output_close(GSF_OUTPUT(gsfparams.outole));
		g_object_unref(gsfparams.outole);
		g_object_unref(gsfparams.sink);
	}
#else
	ret = append_signature(sig, cursig, type, &options, &padlen, &len, outdata);
#endif /* WITH_GSF */
	if (ret)
		DO_EXIT_0("Append signature to outfile failed\n");

skip_signing:

	update_data_size(type, cmd, &header, padlen, len, outdata);

	BIO_free_all(hash);
	hash = outdata = NULL;

	if (!ret && cmd == CMD_ATTACH) {
		ret = check_attached_data(type, &header, &options);
		if (!ret)
			printf("Signature successfully attached\n");
		/* else
		 * the new signature has been successfully appended to the outfile
		 * but only its verification failed (incorrect verification parameters?)
		 * so the output file is not deleted
		 */
	}

err_cleanup:

	if (cmd != CMD_ADD)
		PKCS7_free(cursig);
	PKCS7_free(sig);
	if (hash)
		BIO_free_all(hash);
	if (outdata)
		unlink(options.outfile);
#ifdef WIN32
	UnmapViewOfFile(indata);
#else
	munmap(indata, filesize);
#endif
	free_crypto_params(&cparams);
	free_options(&options);
	if (ret)
		ERR_print_errors_fp(stdout);
#ifdef WITH_GSF
	if (gsf_initialized)
		gsf_shutdown();
#endif

	printf(ret ? "Failed\n" : "Succeeded\n");
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
