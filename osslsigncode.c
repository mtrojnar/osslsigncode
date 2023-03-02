/*
   OpenSSL based Authenticode signing for PE/MSI/Java CAB files.

   Copyright (C) 2005-2015 Per Allansson <pallansson@gmail.com>
   Copyright (C) 2018-2023 Michał Trojnara <Michal.Trojnara@stunnel.org>

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

#include "osslsigncode.h"
#include "helpers.h"

/*
 * ASN.1 definitions (more or less from official MS Authenticode docs)
 */
ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(CatalogAuthAttr) = {
	ASN1_SIMPLE(CatalogAuthAttr, type, ASN1_OBJECT),
	ASN1_OPT(CatalogAuthAttr, contents, ASN1_ANY)
} ASN1_SEQUENCE_END(CatalogAuthAttr)

IMPLEMENT_ASN1_FUNCTIONS(CatalogAuthAttr)

ASN1_SEQUENCE(MessageImprint) = {
	ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

#ifdef ENABLE_CURL

ASN1_SEQUENCE(TimeStampRequestBlob) = {
	ASN1_SIMPLE(TimeStampRequestBlob, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TimeStampRequestBlob, signature, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(TimeStampRequestBlob)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequestBlob)

ASN1_SEQUENCE(TimeStampRequest) = {
	ASN1_SIMPLE(TimeStampRequest, type, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampRequest, blob, TimeStampRequestBlob)
} ASN1_SEQUENCE_END(TimeStampRequest)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequest)

/* RFC3161 Time stamping */

ASN1_SEQUENCE(PKIStatusInfo) = {
	ASN1_SIMPLE(PKIStatusInfo, status, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(PKIStatusInfo, statusString, ASN1_UTF8STRING),
	ASN1_OPT(PKIStatusInfo, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PKIStatusInfo)

IMPLEMENT_ASN1_FUNCTIONS(PKIStatusInfo)

ASN1_SEQUENCE(TimeStampResp) = {
	ASN1_SIMPLE(TimeStampResp, status, PKIStatusInfo),
	ASN1_OPT(TimeStampResp, token, PKCS7)
} ASN1_SEQUENCE_END(TimeStampResp)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampResp)

ASN1_SEQUENCE(TimeStampReq) = {
	ASN1_SIMPLE(TimeStampReq, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, messageImprint, MessageImprint),
	ASN1_OPT   (TimeStampReq, reqPolicy, ASN1_OBJECT),
	ASN1_OPT   (TimeStampReq, nonce, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampReq, certReq, ASN1_FBOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampReq, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampReq)

#endif /* ENABLE_CURL */

ASN1_SEQUENCE(TimeStampAccuracy) = {
	ASN1_OPT(TimeStampAccuracy, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(TimeStampAccuracy, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(TimeStampAccuracy, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TimeStampAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampAccuracy)

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


#ifdef ENABLE_CURL

static int blob_has_nl = 0;

/*
 * Callback for writing received data
 */
static size_t curl_write(void *ptr, size_t sz, size_t nmemb, void *stream)
{
	size_t written, len = sz * nmemb;

	if (len > 0 && !blob_has_nl) {
		if (memchr(ptr, '\n', len))
			blob_has_nl = 1;
	}
	if (!BIO_write_ex((BIO*)stream, ptr, len, &written) || written != len)
		return 0; /* FAILED */
	return written;
}

/*
 * [in] url: URL of the Time-Stamp Authority server
 * [in] http_code: curlinfo response code
 * [out] none
 */
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
 * [in, out] tdata: TYPE_DATA structure
 * [out] pointer to BIO
 */
static BIO *bio_encode_rfc3161_request(TYPE_DATA *tdata)
{
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	PKCS7_SIGNER_INFO *si;
	u_char mdbuf[EVP_MAX_MD_SIZE];
	TimeStampReq *req;
	BIO *bout, *bhash;
	u_char *p;
	int len;

	signer_info = PKCS7_get_signer_info(tdata->sign->sig);
	if (!signer_info)
		return NULL; /* FAILED */

	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return NULL; /* FAILED */

	bhash = BIO_new(BIO_f_md());
	if (!BIO_set_md(bhash, tdata->options->md)) {
		printf("Unable to set the message digest of BIO\n");
		BIO_free_all(bhash);
		return NULL;  /* FAILED */
	}
	BIO_push(bhash, BIO_new(BIO_s_null()));
	BIO_write(bhash, si->enc_digest->data, si->enc_digest->length);
	BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(tdata->options->md));
	BIO_free_all(bhash);

	req = TimeStampReq_new();
	ASN1_INTEGER_set(req->version, 1);
	req->messageImprint->digestAlgorithm->algorithm = OBJ_nid2obj(EVP_MD_nid(tdata->options->md));
	req->messageImprint->digestAlgorithm->parameters = ASN1_TYPE_new();
	req->messageImprint->digestAlgorithm->parameters->type = V_ASN1_NULL;
	ASN1_OCTET_STRING_set(req->messageImprint->digest, mdbuf, EVP_MD_size(tdata->options->md));
	req->certReq = 0xFF;

	len = i2d_TimeStampReq(req, NULL);
	p = OPENSSL_malloc((size_t)len);
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
 * [in, out] tdata: TYPE_DATA structure
 * [out] pointer to BIO
 */
static BIO *bio_encode_authenticode_request(TYPE_DATA *tdata)
{
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	PKCS7_SIGNER_INFO *si;
	TimeStampRequest *req;
	BIO *bout, *b64;
	u_char *p;
	int len;

	signer_info = PKCS7_get_signer_info(tdata->sign->sig);
	if (!signer_info)
		return 0; /* FAILED */

	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 0; /* FAILED */

	req = TimeStampRequest_new();
	req->type = OBJ_txt2obj(SPC_TIME_STAMP_REQUEST_OBJID, 1);
	req->blob->type = OBJ_nid2obj(NID_pkcs7_data);
	req->blob->signature = si->enc_digest;

	len = i2d_TimeStampRequest(req, NULL);
	p = OPENSSL_malloc((size_t)len);
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
 * [in, out] tdata: TYPE_DATA structure
 * [in] bin: BIO with curl data
 * [in] verbose: additional output mode
 * [out] CURLcode
 */
static CURLcode decode_rfc3161_response(TYPE_DATA *tdata, BIO *bin, int verbose)
{
	PKCS7_SIGNER_INFO *si;
	STACK_OF(X509_ATTRIBUTE) *attrs;
	TimeStampResp *reply;
	u_char *p;
	int i, len;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info = PKCS7_get_signer_info(tdata->sign->sig);

	if (!signer_info)
		return 1; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 1; /* FAILED */

	reply = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TimeStampResp), bin, NULL);
	BIO_free_all(bin);
	if (!reply || !reply->status)
		return 1; /* FAILED */
	if (ASN1_INTEGER_get(reply->status->status) != 0) {
		if (verbose) {
			printf("Timestamping failed: status %ld\n", ASN1_INTEGER_get(reply->status->status));
			for (i = 0; i < sk_ASN1_UTF8STRING_num(reply->status->statusString); i++) {
				ASN1_UTF8STRING *status = sk_ASN1_UTF8STRING_value(reply->status->statusString, i);
				printf("%s\n", ASN1_STRING_get0_data(status));
			}
		}
		TimeStampResp_free(reply);
		return 1; /* FAILED */
	}
	if (((len = i2d_PKCS7(reply->token, NULL)) <= 0) || (p = OPENSSL_malloc((size_t)len)) == NULL) {
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

	PKCS7_set_attributes(si, attrs);
	sk_X509_ATTRIBUTE_pop_free(attrs, X509_ATTRIBUTE_free);
	return 0; /* OK */
}

/*
 * Decode a curl response from BIO.
 * If successful the authenticode timestamp will be written into
 * the PKCS7 SignerInfo structure as an unauthorized attribute - cont[1].
 * [in, out] tdata: TYPE_DATA structure
 * [in] bin: BIO with curl data
 * [in] verbose: additional output mode
 * [out] CURLcode
 */
static CURLcode decode_authenticode_response(TYPE_DATA *tdata, BIO *bin, int verbose)
{
	PKCS7 *p7;
	PKCS7_SIGNER_INFO *info, *si;
	STACK_OF(X509_ATTRIBUTE) *attrs;
	BIO* b64, *b64_bin;
	u_char *p;
	int len, i;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;

	b64 = BIO_new(BIO_f_base64());
	if (!blob_has_nl)
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	b64_bin = BIO_push(b64, bin);
	p7 = d2i_PKCS7_bio(b64_bin, NULL);
	BIO_free_all(b64_bin);
	if (p7 == NULL)
		return 1; /* FAILED */

	for(i = sk_X509_num(p7->d.sign->cert)-1; i>=0; i--)
		PKCS7_add_certificate(tdata->sign->sig, sk_X509_value(p7->d.sign->cert, i));

	signer_info = PKCS7_get_signer_info(p7);
	if (!signer_info)
		return 1; /* FAILED */
	info = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!info)
		return 1; /* FAILED */
	if (((len = i2d_PKCS7_SIGNER_INFO(info, NULL)) <= 0) || (p = OPENSSL_malloc((size_t)len)) == NULL) {
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
	attrs = X509at_add1_attr_by_txt(&attrs, PKCS9_COUNTER_SIGNATURE, V_ASN1_SET, p, len);
	OPENSSL_free(p);

	signer_info = PKCS7_get_signer_info(tdata->sign->sig);
	if (!signer_info)
		return 1; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
	if (!si)
		return 1; /* FAILED */
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
 * [in, out] tdata: TYPE_DATA structure
 * [in] url: URL of the Time-Stamp Authority server
 * [in] rfc3161: Authenticode / RFC3161 Timestamp switch
 * [out] return code
 */
static int add_timestamp(TYPE_DATA *tdata, char *url, int rfc3161)
{
	CURL *curl;
	struct curl_slist *slist = NULL;
	CURLcode res;
	BIO *bout, *bin;
	u_char *p = NULL;
	long len = 0;
	int verbose = tdata->options->verbose || tdata->options->ntsurl == 1;

	if (!url)
		return 1; /* FAILED */

	/* Encode timestamp request */
	if (rfc3161) {
		bout = bio_encode_rfc3161_request(tdata);
	} else {
		bout = bio_encode_authenticode_request(tdata);
	}
	if (!bout)
		return 1; /* FAILED */

	/* Start a libcurl easy session and set options for a curl easy handle */
	curl = curl_easy_init();
	if (tdata->options->proxy) {
		res = curl_easy_setopt(curl, CURLOPT_PROXY, tdata->options->proxy);
		if (res != CURLE_OK) {
			printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
		}
		if (!strncmp("http:", tdata->options->proxy, 5)) {
			res = curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
			if (res != CURLE_OK) {
				printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
			}
		}
		if (!strncmp("socks:", tdata->options->proxy, 6)) {
			res = curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
			if (res != CURLE_OK) {
				printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
			}
		}
	}
	res = curl_easy_setopt(curl, CURLOPT_URL, url);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}
	/*
	 * ask libcurl to show us the verbose output
	 * curl_easy_setopt(curl, CURLOPT_VERBOSE, 42);
	 */
	if (tdata->options->noverifypeer) {
		res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
		if (res != CURLE_OK) {
			printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
		}
	}

	if (rfc3161) {
		slist = curl_slist_append(slist, "Content-Type: application/timestamp-query");
		slist = curl_slist_append(slist, "Accept: application/timestamp-reply");
	} else {
		slist = curl_slist_append(slist, "Content-Type: application/octet-stream");
		slist = curl_slist_append(slist, "Accept: application/octet-stream");
	}
	slist = curl_slist_append(slist, "User-Agent: Transport");
	slist = curl_slist_append(slist, "Cache-Control: no-cache");
	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}

	len = BIO_get_mem_data(bout, &p);
	res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}
	res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)p);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}

	bin = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(bin, 0);
	res = curl_easy_setopt(curl, CURLOPT_POST, 1);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}
	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, bin);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}
	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
	if (res != CURLE_OK) {
		printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
	}
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
			res = decode_rfc3161_response(tdata, bin, verbose);
		else
			res = decode_authenticode_response(tdata, bin, verbose);
		if (res && verbose)
			print_timestamp_error(url, http_code);
	}
	/* End a libcurl easy handle */
	curl_easy_cleanup(curl);
	return (int)res;
}

/*
 * [in, out] tdata: TYPE_DATA structure
 * [out] return code
 */
static int add_timestamp_authenticode(TYPE_DATA *tdata)
{
	int i;
	for (i=0; i<tdata->options->nturl; i++) {
		if (!add_timestamp(tdata, tdata->options->turl[i], 0))
			return 1; /* OK */
	}
	return 0; /* FAILED */
}

/*
 * [in, out] tdata: TYPE_DATA structure
 * [out] return code
 */
static int add_timestamp_rfc3161(TYPE_DATA *tdata)
{
	int i;
	for (i=0; i<tdata->options->ntsurl; i++) {
		if (!add_timestamp(tdata, tdata->options->tsurl[i], 1))
			return 1; /* OK */
	}
	return 0; /* FAILED */
}
#endif /* ENABLE_CURL */

/*
 * [in, out] tdata: TYPE_DATA structure
 * [out] return code
 */
static int add_unauthenticated_blob(TYPE_DATA *tdata)
{
	PKCS7_SIGNER_INFO *si;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
	ASN1_STRING *astr;
	u_char *p = NULL;
	int nid, len = 1024+4;
	/* Length data for ASN1 attribute plus prefix */
	const char prefix[] = "\x0c\x82\x04\x00---BEGIN_BLOB---";
	const char postfix[] = "---END_BLOB---";

	signer_info = PKCS7_get_signer_info(tdata->sign->sig);
	if (!signer_info)
		return 0; /* FAILED */
	si = sk_PKCS7_SIGNER_INFO_value(tdata->sign->sig->d.sign->signer_info, 0);
	if (!si)
		return 0; /* FAILED */
	if ((p = OPENSSL_malloc((size_t)len)) == NULL)
		return 0; /* FAILED */
	memset(p, 0, (size_t)len);
	memcpy(p, prefix, sizeof prefix);
	memcpy(p + len - sizeof postfix, postfix, sizeof postfix);
	astr = ASN1_STRING_new();
	ASN1_STRING_set(astr, p, len);
	nid = OBJ_create(SPC_UNAUTHENTICATED_DATA_BLOB_OBJID,
		"unauthenticatedData", "unauthenticatedData");
	PKCS7_add_attribute(si, nid, V_ASN1_SEQUENCE, astr);
	OPENSSL_free(p);
	return 1; /* OK */
}

/*
 * [in, out] tdata: TYPE_DATA structure
 * [out] return code
 */
static int check_timestamp_and_blob(TYPE_DATA *tdata)
{
#ifdef ENABLE_CURL
	/* add counter-signature/timestamp */
	if (tdata->options->nturl && !add_timestamp_authenticode(tdata)) {
		printf("%s\n%s\n", "Authenticode timestamping failed",
			"Use the \"-ts\" option to add the RFC3161 Time-Stamp Authority or choose another one Authenticode Time-Stamp Authority");
		return 1; /* FAILED */
	}
	if (tdata->options->ntsurl && !add_timestamp_rfc3161(tdata)) {
		printf("%s\n%s\n", "RFC 3161 timestamping failed",
			"Use the \"-t\" option to add the Authenticode Time-Stamp Authority or choose another one RFC3161 Time-Stamp Authority");
		return 1; /* FAILED */
	}
#endif /* ENABLE_CURL */
	if (tdata->options->addBlob && !add_unauthenticated_blob(tdata)) {
		printf("Adding unauthenticated blob failed\n");
		return 1; /* FAILED */
	}
	return 0; /* OK */
}

/*
 * [in] txt, list
 * [out] return code
 */
static int on_list(const char *txt, const char *list[])
{
	while (*list)
		if (!strcmp(txt, *list++))
			return 1; /* OK */
	return 0; /* FAILED */
}

/*
 * [in] argv0, cmd
 * [out] none
 */
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
		printf("%1s[ sign ] ( -certs | -spc <certfile> -key <keyfile> | -pkcs12 <pkcs12file> |\n", "");
		printf("%12s  [ -pkcs11engine <engine> ] -pkcs11module <module> -pkcs11cert <pkcs11 cert id> |\n", "");
		printf("%12s  -certs <certfile> -key <pkcs11 key id>)\n", "");
#if OPENSSL_VERSION_NUMBER>=0x30000000L
		printf("%12s[ -nolegacy ]\n", "");
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
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
		printf("%12s[ -time <unix-time> ]\n", "");
		printf("%12s[ -addUnauthenticatedBlob ]\n", "");
		printf("%12s[ -nest ]\n", "");
		printf("%12s[ -verbose ]\n", "");
		printf("%12s[ -add-msi-dse ]\n", "");
		printf("%12s[ -in ] <infile> [-out ] <outfile>\n\n", "");
	}
	if (on_list(cmd, cmds_add)) {
		printf("%1sadd [-addUnauthenticatedBlob]\n", "");
#ifdef ENABLE_CURL
		printf("%12s[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer  ]\n", "");
		printf("%12s[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n", "");
#endif /* ENABLE_CURL */
		printf("%12s[ -h {md5,sha1,sha2(56),sha384,sha512} ]\n", "");
		printf("%12s[ -verbose ]\n", "");
		printf("%12s[ -add-msi-dse ]\n", "");
		printf("%12s[ -in ] <infile> [ -out ] <outfile>\n\n", "");
	}
	if (on_list(cmd, cmds_attach)) {
		printf("%1sattach-signature [ -sigin ] <sigfile>\n", "");
		printf("%12s[ -CAfile <infile> ]\n", "");
		printf("%12s[ -CRLfile <infile> ]\n", "");
		printf("%12s[ -TSA-CAfile <infile> ]\n", "");
		printf("%12s[ -TSA-CRLfile <infile> ]\n", "");
		printf("%12s[ -time <unix-time> ]\n", "");
		printf("%12s[ -h {md5,sha1,sha2(56),sha384,sha512} ]\n", "");
		printf("%12s[ -require-leaf-hash {md5,sha1,sha2(56),sha384,sha512}:XXXXXXXXXXXX... ]\n", "");
		printf("%12s[ -nest ]\n", "");
		printf("%12s[ -add-msi-dse ]\n", "");
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
		printf("%12s[ -c | -catalog <infile> ]\n", "");
		printf("%12s[ -CAfile <infile> ]\n", "");
		printf("%12s[ -CRLfile <infile> ]\n", "");
		printf("%12s[ -TSA-CAfile <infile> ]\n", "");
		printf("%12s[ -TSA-CRLfile <infile> ]\n", "");
		printf("%12s[ -ignore-timestamp ]\n", "");
		printf("%12s[ -time <unix-time> ]\n", "");
		printf("%12s[ -require-leaf-hash {md5,sha1,sha2(56),sha384,sha512}:XXXXXXXXXXXX... ]\n", "");
		printf("%12s[ -verbose ]\n\n", "");
	}
}

/*
 * [in] argv0, cmd
 * [out] none
 */
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
	const char *cmds_add_msi_dse[] = {"add", "attach-signature", "sign", NULL};
	const char *cmds_addUnauthenticatedBlob[] = {"sign", "add", NULL};
#ifdef PROVIDE_ASKPASS
	const char *cmds_askpass[] = {"sign", NULL};
#endif /* PROVIDE_ASKPASS */
	const char *cmds_CAfile[] = {"attach-signature", "verify", NULL};
	const char *cmds_catalog[] = {"verify", NULL};
	const char *cmds_certs[] = {"sign", NULL};
	const char *cmds_comm[] = {"sign", NULL};
	const char *cmds_CRLfile[] = {"attach-signature", "verify", NULL};
	const char *cmds_CRLfileTSA[] = {"attach-signature", "verify", NULL};
	const char *cmds_h[] = {"add", "attach-signature", "sign", NULL};
	const char *cmds_i[] = {"sign", NULL};
	const char *cmds_in[] = {"add", "attach-signature", "extract-signature", "remove-signature", "sign", "verify", NULL};
	const char *cmds_jp[] = {"sign", NULL};
	const char *cmds_key[] = {"sign", NULL};
#if OPENSSL_VERSION_NUMBER>=0x30000000L
	const char *cmds_nolegacy[] = {"sign", NULL};
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
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
	const char *cmds_require_leaf_hash[] = {"attach-signature", "verify", NULL};
	const char *cmds_sigin[] = {"attach-signature", NULL};
	const char *cmds_time[] = {"attach-signature", "sign", "verify", NULL};
	const char *cmds_ignore_timestamp[] = {"verify", NULL};
#ifdef ENABLE_CURL
	const char *cmds_t[] = {"add", "sign", NULL};
	const char *cmds_ts[] = {"add", "sign", NULL};
#endif /* ENABLE_CURL */
	const char *cmds_CAfileTSA[] = {"attach-signature", "verify", NULL};
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
	if (on_list(cmd, cmds_add_msi_dse))
		printf("%-24s= sign a MSI file with the add-msi-dse option\n", "-add-msi-dse");
	if (on_list(cmd, cmds_addUnauthenticatedBlob))
		printf("%-24s= add an unauthenticated blob to the PE/MSI file\n", "-addUnauthenticatedBlob");
#ifdef PROVIDE_ASKPASS
	if (on_list(cmd, cmds_askpass))
		printf("%-24s= ask for the private key password\n", "-askpass");
#endif /* PROVIDE_ASKPASS */
	if (on_list(cmd, cmds_catalog))
		printf("%-24s= specifies the catalog file by name\n", "-c, -catalog");
	if (on_list(cmd, cmds_CAfile))
		printf("%-24s= the file containing one or more trusted certificates in PEM format\n", "-CAfile");
	if (on_list(cmd, cmds_certs))
		printf("%-24s= the signing certificate to use\n", "-certs, -spc");
	if (on_list(cmd, cmds_comm))
		printf("%-24s= set commercial purpose (default: individual purpose)\n", "-comm");
	if (on_list(cmd, cmds_CRLfile))
		printf("%-24s= the file containing one or more CRLs in PEM format\n", "-CRLfile");
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
#if OPENSSL_VERSION_NUMBER>=0x30000000L
	if (on_list(cmd, cmds_nolegacy))
		printf("%-24s= disable legacy mode and don't automatically load the legacy provider\n", "-nolegacy");
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
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
		printf("%-24s= PKCS#11 engine\n", "-pkcs11engine");
	if (on_list(cmd, cmds_pkcs11module))
		printf("%-24s= PKCS#11 module\n", "-pkcs11module");
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
	if (on_list(cmd, cmds_ignore_timestamp))
		printf("%-24s= disable verification of the Timestamp Server signature\n", "-ignore-timestamp");
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
	if (on_list(cmd, cmds_time))
		printf("%-24s= the unix-time to set the signing and/or verifying time\n", "-time");
	if (on_list(cmd, cmds_CAfileTSA))
		printf("%-24s= the file containing one or more Time-Stamp Authority certificates in PEM format\n", "-TSA-CAfile");
	if (on_list(cmd, cmds_CRLfileTSA))
		printf("%-24s= the file containing one or more Time-Stamp Authority CRLs in PEM format\n", "-TSA-CRLfile");
	if (on_list(cmd, cmds_verbose))
		printf("%-24s= include additional output in the log\n", "-verbose");
	usage(argv0, cmd);
}

/*
 * [in] bin: certfile BIO
 * [in] certpass: NULL
 * [out] pointer to STACK_OF(X509) structure
 */
static STACK_OF(X509) *X509_chain_read_certs(BIO *bin, char *certpass)
{
	STACK_OF(X509) *certs = sk_X509_new_null();
	X509 *x509;
	(void)BIO_seek(bin, 0);
	x509 = PEM_read_bio_X509(bin, NULL, NULL, certpass);
	while (x509) {
		sk_X509_push(certs, x509);
		x509 = PEM_read_bio_X509(bin, NULL, NULL, certpass);
	}
	ERR_clear_error();
	if (!sk_X509_num(certs)) {
		sk_X509_free(certs);
		return NULL;
	}
	return certs;
}

#ifdef PROVIDE_ASKPASS
/*
 * [in] prompt: "Password: "
 * [out] password
 */
static char *getpassword(const char *prompt)
{
#ifdef HAVE_TERMIOS_H
	struct termios ofl, nfl;
	char *p, passbuf[1024], *pass;

	fputs(prompt, stdout);

	tcgetattr(fileno(stdin), &ofl);
	nfl = ofl;
	nfl.c_lflag &= ~(unsigned int)ECHO;
	nfl.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &nfl) != 0) {
		printf("Failed to set terminal attributes\n");
		return NULL;
	}
	p = fgets(passbuf, sizeof passbuf, stdin);
	if (tcsetattr(fileno(stdin), TCSANOW, &ofl) != 0)
		printf("Failed to restore terminal attributes\n");
	if (!p) {
		printf("Failed to read password\n");
		return NULL;
	}
	passbuf[strlen(passbuf)-1] = 0x00;
	pass = OPENSSL_strdup(passbuf);
	memset(passbuf, 0, sizeof passbuf);
	return pass;
#else
	return getpass(prompt);
#endif
}
#endif

/*
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_password(GLOBAL_OPTIONS *options)
{
	char passbuf[4096];
	int passlen;
	const u_char utf8_bom[] = {0xef, 0xbb, 0xbf};

	if (options->readpass) {
#ifdef WIN32
		HANDLE fhandle, fmap;
		LPVOID faddress;
		fhandle = CreateFile(options->readpass, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (fhandle == INVALID_HANDLE_VALUE) {
			return 0; /* FAILED */
		}
		fmap = CreateFileMapping(fhandle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (fmap == NULL) {
			return 0; /* FAILED */
		}
		faddress = MapViewOfFile(fmap, FILE_MAP_READ, 0, 0, 0);
		CloseHandle(fmap);
		if (faddress == NULL) {
			return 0; /* FAILED */
		}
		passlen = (int)GetFileSize(fhandle, NULL);
		memcpy(passbuf, faddress, passlen);
		UnmapViewOfFile(faddress);
		CloseHandle(fhandle);
#else
		int passfd = open(options->readpass, O_RDONLY);
		if (passfd < 0) {
			return 0; /* FAILED */
		}
		passlen = (int)read(passfd, passbuf, sizeof passbuf - 1);
		close(passfd);
#endif /* WIN32 */
		if (passlen <= 0) {
			return 0; /* FAILED */
		}
		while (passlen > 0 && (passbuf[passlen-1] == 0x0a || passbuf[passlen-1] == 0x0d)) {
			passlen--;
		}
		passbuf[passlen] = 0x00;
		if (!memcmp(passbuf, utf8_bom, sizeof utf8_bom)) {
			options->pass = OPENSSL_strdup(passbuf + sizeof utf8_bom);
		} else {
			options->pass = OPENSSL_strdup(passbuf);
		}
		memset(passbuf, 0, sizeof passbuf);
#ifdef PROVIDE_ASKPASS
	} else if (options->askpass) {
		options->pass = getpassword("Password: ");
#endif /* PROVIDE_ASKPASS */
	}
	return 1; /* OK */
}

/*
 * Parse a PKCS#12 container with certificates and a private key.
 * If successful the private key will be written to options->pkey,
 * the corresponding certificate to options->cert
 * and any additional certificates to options->certs.
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_pkcs12file(GLOBAL_OPTIONS *options)
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
	if (!PKCS12_parse(p12, options->pass ? options->pass : "", &options->pkey, &options->cert, &options->certs)) {
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

/*
 * Obtain a copy of the whole X509_CRL chain
 * [in] chain: STACK_OF(X509_CRL) structure
 * [out] pointer to STACK_OF(X509_CRL) structure
 */
static STACK_OF(X509_CRL) *X509_CRL_chain_up_ref(STACK_OF(X509_CRL) *chain)
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
 * If successful all certificates will be written to options->certs
 * and optional CRLs will be written to options->crls.
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_certfile(GLOBAL_OPTIONS *options)
{
	BIO *btmp;
	int ret = 0;

	btmp = BIO_new_file(options->certfile, "rb");
	if (!btmp) {
		printf("Failed to read certificate file: %s\n", options->certfile);
		return 0; /* FAILED */
	}
	/* .pem certificate file */
	options->certs = X509_chain_read_certs(btmp, NULL);

	/* .der certificate file */
	if (!options->certs) {
		X509 *x = NULL;
		(void)BIO_seek(btmp, 0);
		if (d2i_X509_bio(btmp, &x)) {
			options->certs = sk_X509_new_null();
			if (!sk_X509_push(options->certs, x)) {
				X509_free(x);
				goto out; /* FAILED */
			}
			printf("Warning: The certificate file contains a single x509 certificate\n");
		}
	}

	/* .spc or .p7b certificate file (PKCS#7 structure) */
	if (!options->certs) {
		PKCS7 *p7;
		(void)BIO_seek(btmp, 0);
		p7 = d2i_PKCS7_bio(btmp, NULL);
		if (!p7)
			goto out; /* FAILED */
		options->certs = X509_chain_up_ref(p7->d.sign->cert);

		/* additional CRLs may be supplied as part of a PKCS#7 signed data structure */
		if (p7->d.sign->crl)
			options->crls = X509_CRL_chain_up_ref(p7->d.sign->crl);
		PKCS7_free(p7);
	}

	ret = 1; /* OK */
out:
	if (ret == 0)
		printf("No certificate found\n");
	BIO_free(btmp);
	return ret;
}

/*
 * Load additional (cross) certificates from a .pem file
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_xcertfile(GLOBAL_OPTIONS *options)
{
	BIO *btmp;
	int ret = 0;

	btmp = BIO_new_file(options->xcertfile, "rb");
	if (!btmp) {
		printf("Failed to read cross certificates file: %s\n", options->xcertfile);
		return 0; /* FAILED */
	}
	options->xcerts = X509_chain_read_certs(btmp, NULL);
	if (!options->xcerts) {
		printf("Failed to read cross certificates file: %s\n", options->xcertfile);
		goto out; /* FAILED */
	}

	ret = 1; /* OK */
out:
	BIO_free(btmp);
	return ret;
}

/*
 * Load the private key from a file
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_keyfile(GLOBAL_OPTIONS *options)
{
	BIO *btmp;
	int ret = 0;

	btmp = BIO_new_file(options->keyfile, "rb");
	if (!btmp) {
		printf("Failed to read private key file: %s\n", options->keyfile);
		return 0; /* FAILED */
	}
	if (((options->pkey = d2i_PrivateKey_bio(btmp, NULL)) == NULL &&
			(BIO_seek(btmp, 0) == 0) &&
			(options->pkey = PEM_read_bio_PrivateKey(btmp, NULL, NULL, options->pass ? options->pass : NULL)) == NULL &&
			(BIO_seek(btmp, 0) == 0) &&
			(options->pkey = PEM_read_bio_PrivateKey(btmp, NULL, NULL, NULL)) == NULL)) {
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
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] PVK file
 */
static char *find_pvk_key(GLOBAL_OPTIONS *options)
{
	u_char magic[4];
	/* Microsoft Private Key format Header Hexdump */
	const u_char pvkhdr[4] = {0x1e, 0xf1, 0xb5, 0xb0};
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

/*
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_pvk_key(GLOBAL_OPTIONS *options)
{
	BIO *btmp;

	btmp = BIO_new_file(options->pvkfile, "rb");
	if (!btmp) {
		printf("Failed to read private key file: %s\n", options->pvkfile);
		return 0; /* FAILED */
	}
	options->pkey = b2i_PVK_bio(btmp, NULL, options->pass ? options->pass : NULL);
	if (!options->pkey && options->askpass) {
		(void)BIO_seek(btmp, 0);
		options->pkey = b2i_PVK_bio(btmp, NULL, NULL);
	}
	BIO_free(btmp);
	if (!options->pkey) {
		printf("Failed to decode private key file: %s\n", options->pvkfile);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

#ifndef OPENSSL_NO_ENGINE

/*
 * Load an engine in a shareable library
 * [in] options: GLOBAL_OPTIONS structure
 * [out] pointer to ENGINE
 */
static ENGINE *engine_dynamic(GLOBAL_OPTIONS *options)
{
	ENGINE *engine;
	char *id;

	engine = ENGINE_by_id("dynamic");
	if (!engine) {
		printf("Failed to load 'dynamic' engine\n");
		return NULL; /* FAILED */
	}
	if (options->p11engine) { /* strip directory and extension */
		char *ptr;

		ptr = strrchr(options->p11engine, '/');
		if (!ptr) /* no slash -> try backslash */
			ptr = strrchr(options->p11engine, '\\');
		if (ptr) /* directory separator found */
			ptr++; /* skip it */
		else /* directory separator not found */
			ptr = options->p11engine;
		id = OPENSSL_strdup(ptr);
		ptr = strchr(id, '.');
		if (ptr) /* file extensions found */
			*ptr = '\0'; /* remove them */
	} else {
		id = OPENSSL_strdup("pkcs11");
	}
	if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", options->p11engine, 0)
			|| !ENGINE_ctrl_cmd_string(engine, "ID", id, 0)
			|| !ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "1", 0)
			|| !ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0)) {
		printf("Failed to set 'dynamic' engine\n");
		ENGINE_free(engine);
		engine = NULL; /* FAILED */
	}
	OPENSSL_free(id);
	return engine;
}

/*
 * Load a pkcs11 engine
 * [in] none
 * [out] pointer to ENGINE
 */
static ENGINE *engine_pkcs11()
{
	ENGINE *engine = ENGINE_by_id("pkcs11");
	if (!engine) {
		printf("Failed to find and load 'pkcs11' engine\n");
		return NULL; /* FAILED */
	}
	return engine; /* OK */
}

/*
 * Load the private key and the signer certificate from a security token
 * [in, out] options: GLOBAL_OPTIONS structure
 * [in] engine: ENGINE structure
 * [out] return code
 */
static int read_token(GLOBAL_OPTIONS *options, ENGINE *engine)
{
	if (options->p11module && !ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", options->p11module, 0)) {
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
		printf("Failed to initialize pkcs11 engine\n");
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
			options->cert = parms.cert;
	}

	options->pkey = ENGINE_load_private_key(engine, options->keyfile, NULL, NULL);
	/* Free the functional reference from ENGINE_init */
	ENGINE_finish(engine);
	if (!options->pkey) {
		printf("Failed to load private key %s\n", options->keyfile);
		return 0; /* FAILED */
	}
	return 1; /* OK */
}
#endif /* OPENSSL_NO_ENGINE */

/*
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int read_crypto_params(GLOBAL_OPTIONS *options)
{
	int ret = 0;

	/* Microsoft Private Key format support */
	options->pvkfile = find_pvk_key(options);
	if (options->pvkfile) {
		if (!read_certfile(options) || !read_pvk_key(options))
			goto out; /* FAILED */

	/* PKCS#12 container with certificates and the private key ("-pkcs12" option) */
	} else if (options->pkcs12file) {
		if (!read_pkcs12file(options))
			goto out; /* FAILED */

#ifndef OPENSSL_NO_ENGINE
	/* PKCS11 engine and module support */
	} else if ((options->p11engine) || (options->p11module)) {
		ENGINE *engine;

		if (options->p11engine)
			engine = engine_dynamic(options);
		else
			engine = engine_pkcs11();
		if (!engine)
			goto out; /* FAILED */
		printf("Engine \"%s\" set.\n", ENGINE_get_id(engine));

		/* Load the private key and the signer certificate from the security token */
		if (!read_token(options, engine))
			goto out; /* FAILED */

		/* Load the signer certificate and the whole certificate chain from a file */
		if (options->certfile && !read_certfile(options))
			goto out; /* FAILED */

	/* PEM / DER / SPC file format support */
	} else if (!read_certfile(options) || !read_keyfile(options))
		goto out; /* FAILED */
#endif /* OPENSSL_NO_ENGINE */

	/* Load additional (cross) certificates ("-ac" option) */
	if (options->xcertfile && !read_xcertfile(options))
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

/*
 * [in] none
 * [out] default CAfile
 */
static char *get_cafile(void)
{
#ifndef WIN32
    const char *files[] = {
	    "/etc/ssl/certs/ca-certificates.crt",
	    "/etc/pki/tls/certs/ca-bundle.crt",
	    "/usr/share/ssl/certs/ca-bundle.crt",
	    "/usr/local/share/certs/ca-root-nss.crt",
	    "/etc/ssl/cert.pem",
	    NULL
	};
    int i;

	for (i=0; files[i]; i++) {
	    if (!access(files[i], R_OK)) {
	        return OPENSSL_strdup(files[i]);
	    }
	}
#endif
	return NULL;
}

static void print_version(void)
{
#ifdef PACKAGE_STRING
	printf("%s, using:\n", PACKAGE_STRING);
#else /* PACKAGE_STRING */
	printf("%s, using:\n", "osslsigncode custom build");
#endif /* PACKAGE_STRING */
	printf("\t%s (Library: %s)\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
#ifdef ENABLE_CURL
	printf("\t%s\n", curl_version());
#else /* ENABLE_CURL */
	printf("\t%s\n", "no libcurl available");
#endif /* ENABLE_CURL */
#ifdef PACKAGE_BUGREPORT
	printf("\nPlease send bug-reports to " PACKAGE_BUGREPORT "\n");
#endif /* PACKAGE_BUGREPORT */
	printf("\n");
}

/*
 * [in] argv
 * [out] cmd_type_t: command
 */
static cmd_type_t get_command(char **argv)
{
	if (!strcmp(argv[1], "--help")) {
		print_version();
		help_for(argv[0], "all");
		return CMD_HELP;
	} else if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
		print_version();
		return CMD_HELP;
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
	return CMD_DEFAULT;
}

#if OPENSSL_VERSION_NUMBER>=0x30000000L
DEFINE_STACK_OF(OSSL_PROVIDER)
static STACK_OF(OSSL_PROVIDER) *providers = NULL;

static void provider_free(OSSL_PROVIDER *prov)
{
	OSSL_PROVIDER_unload(prov);
}

static void providers_cleanup(void)
{
	sk_OSSL_PROVIDER_pop_free(providers, provider_free);
	providers = NULL;
}

static int provider_load(OSSL_LIB_CTX *libctx, const char *pname)
{
	OSSL_PROVIDER *prov= OSSL_PROVIDER_load(libctx, pname);
	if (prov == NULL) {
		printf("Unable to load provider: %s\n", pname);
		return 0; /* FAILED */
	}
	if (providers == NULL) {
		providers = sk_OSSL_PROVIDER_new_null();
	}
	if (providers == NULL || !sk_OSSL_PROVIDER_push(providers, prov)) {
		providers_cleanup();
		return 0; /* FAILED */
	}
	return 1; /* OK */
}

static int use_legacy(void)
{
	/* load the legacy provider if not loaded already */
	if (!OSSL_PROVIDER_available(NULL, "legacy")) {
		if (!provider_load(NULL, "legacy"))
			return 0; /* FAILED */
		/* load the default provider explicitly */
		if (!provider_load(NULL, "default"))
			return 0; /* FAILED */
	}
	return 1; /* OK */
}
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */

/*
 * [in] input_tdata: TYPE_DATA structure
 * [out] return code
 */
static int check_attached_data(TYPE_DATA *input_tdata)
{
	TYPE_DATA *tdata;
	GLOBAL_OPTIONS *options = NULL;

	options = OPENSSL_memdup(input_tdata->options, sizeof(GLOBAL_OPTIONS));
	if (!options) {
		printf("OPENSSL_memdup error.\n");
		return 1; /* Failed */
	}
	options->infile = input_tdata->options->outfile;
	options->cmd = CMD_VERIFY;

	tdata = file_format_msi.init(options);
	if (!tdata)
		tdata = file_format_pe.init(options);
	if (!tdata)
		tdata = file_format_cab.init(options);
	/* TODO CAT files
	if (!tdata)
		tdata = file_format_cat.init(options); */
	if (!tdata) {
		printf("Corrupted file.\n");
		return 1; /* Failed */
	}
	if (tdata->format->verify_signed_file(tdata)) {
		printf("Signature mismatch\n");
		return 1; /* Failed */
	}
	tdata->format->free_data(tdata);
	tdata->format->cleanup_data(tdata);
	OPENSSL_free(options);
	return 0; /* OK */
}

/*
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] none
 */
static void free_options(GLOBAL_OPTIONS *options)
{
	/* If memory has not been allocated nothing is done */
	OPENSSL_free(options->cafile);
	OPENSSL_free(options->tsa_cafile);
	OPENSSL_free(options->crlfile);
	OPENSSL_free(options->tsa_crlfile);
	/* If key is NULL nothing is done */
	EVP_PKEY_free(options->pkey);
	options->pkey = NULL;
	/* If X509 structure is NULL nothing is done */
	X509_free(options->cert);
	options->cert = NULL;
	/* Free up all elements of sk structure and sk itself */
	sk_X509_pop_free(options->certs, X509_free);
	options->certs = NULL;
	sk_X509_pop_free(options->xcerts, X509_free);
	options->xcerts = NULL;
	sk_X509_CRL_pop_free(options->crls, X509_CRL_free);
	options->crls = NULL;
}

/*
 * [in] argc, argv
 * [in, out] options: GLOBAL_OPTIONS structure
 * [out] return code
 */
static int main_configure(int argc, char **argv, GLOBAL_OPTIONS *options)
{
	int i;
	char *failarg = NULL;
	const char *argv0;
	cmd_type_t cmd = CMD_SIGN;

	argv0 = argv[0];
	if (argc > 1) {
		cmd = get_command(argv);
		if (cmd == CMD_DEFAULT) {
			cmd = CMD_SIGN;
		} else {
			argv++;
			argc--;
		}
	}
	options->cmd = cmd;
	options->md = EVP_sha256();
	options->time = INVALID_TIME;
	options->jp = -1;
#if OPENSSL_VERSION_NUMBER>=0x30000000L
/* Use legacy PKCS#12 container with RC2-40-CBC private key and certificate encryption algorithm */
	options->legacy = 1;
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */

	if (cmd == CMD_HELP) {
		return 0; /* FAILED */
	}
	if (cmd == CMD_VERIFY || cmd == CMD_ATTACH) {
		options->cafile = get_cafile();
		options->tsa_cafile = get_cafile();
	}
	for (argc--,argv++; argc >= 1; argc--,argv++) {
		if (!strcmp(*argv, "-in")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->infile = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->outfile = *(++argv);
		} else if (!strcmp(*argv, "-sigin")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->sigfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && (!strcmp(*argv, "-spc") || !strcmp(*argv, "-certs"))) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->certfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-ac")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->xcertfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-key")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->keyfile = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs12")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->pkcs12file = *(++argv);
		} else if ((cmd == CMD_EXTRACT) && !strcmp(*argv, "-pem")) {
			options->output_pkcs7 = 1;
#ifndef OPENSSL_NO_ENGINE
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11cert")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->p11cert = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11engine")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->p11engine = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pkcs11module")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->p11module = *(++argv);
#endif /* OPENSSL_NO_ENGINE */
#if OPENSSL_VERSION_NUMBER>=0x30000000L
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-nolegacy")) {
			options->legacy = 0;
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-pass")) {
			if (options->askpass || options->readpass) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->pass = OPENSSL_strdup(*(++argv));
			memset(*argv, 0, strlen(*argv));
#ifdef PROVIDE_ASKPASS
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-askpass")) {
			if (options->pass || options->readpass) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->askpass = 1;
#endif
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-readpass")) {
			if (options->askpass || options->pass) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->readpass = *(++argv);
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-comm")) {
			options->comm = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-ph")) {
			options->pagehash = 1;
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-n")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->desc = *(++argv);
		} else if ((cmd == CMD_SIGN|| cmd == CMD_ADD || cmd == CMD_ATTACH)
				&& !strcmp(*argv, "-h")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
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
				return 0; /* FAILED */
			}
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-i")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->url = *(++argv);
		} else if ((cmd == CMD_ATTACH || cmd == CMD_SIGN || cmd == CMD_VERIFY)
				&& (!strcmp(*argv, "-time") || !strcmp(*argv, "-st"))) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->time = (time_t)strtoull(*(++argv), NULL, 10);
#ifdef ENABLE_CURL
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-t")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->turl[options->nturl++] = *(++argv);
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-ts")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->tsurl[options->ntsurl++] = *(++argv);
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-p")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->proxy = *(++argv);
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-noverifypeer")) {
			options->noverifypeer = 1;
#endif
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-addUnauthenticatedBlob")) {
			options->addBlob = 1;
		} else if ((cmd == CMD_SIGN || cmd == CMD_ATTACH) && !strcmp(*argv, "-nest")) {
			options->nest = 1;
		} else if ((cmd == CMD_VERIFY) && !strcmp(*argv, "-ignore-timestamp")) {
			options->ignore_timestamp = 1;
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_VERIFY) && !strcmp(*argv, "-verbose")) {
			options->verbose = 1;
		} else if ((cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH) && !strcmp(*argv, "-add-msi-dse")) {
			options->add_msi_dse = 1;
		} else if ((cmd == CMD_VERIFY) && (!strcmp(*argv, "-c") || !strcmp(*argv, "-catalog"))) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->catalog = *(++argv);
		} else if ((cmd == CMD_VERIFY || cmd == CMD_ATTACH) && !strcmp(*argv, "-CAfile")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			OPENSSL_free(options->cafile);
			options->cafile = OPENSSL_strdup(*++argv);
		} else if ((cmd == CMD_VERIFY || cmd == CMD_ATTACH) && !strcmp(*argv, "-CRLfile")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->crlfile = OPENSSL_strdup(*++argv);
		} else if ((cmd == CMD_VERIFY || cmd == CMD_ATTACH) && (!strcmp(*argv, "-untrusted") || !strcmp(*argv, "-TSA-CAfile"))) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
      }
			OPENSSL_free(options->tsa_cafile);
			options->tsa_cafile = OPENSSL_strdup(*++argv);
		} else if ((cmd == CMD_VERIFY || cmd == CMD_ATTACH) && (!strcmp(*argv, "-CRLuntrusted") || !strcmp(*argv, "-TSA-CRLfile"))) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->tsa_crlfile = OPENSSL_strdup(*++argv);
		} else if ((cmd == CMD_VERIFY || cmd == CMD_ATTACH) && !strcmp(*argv, "-require-leaf-hash")) {
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			options->leafhash = (*++argv);
		} else if ((cmd == CMD_ADD) && !strcmp(*argv, "--help")) {
			help_for(argv0, "add");
			cmd = CMD_HELP;
			return 0; /* FAILED */
		} else if ((cmd == CMD_ATTACH) && !strcmp(*argv, "--help")) {
			help_for(argv0, "attach-signature");
			cmd = CMD_HELP;
			return 0; /* FAILED */
		} else if ((cmd == CMD_EXTRACT) && !strcmp(*argv, "--help")) {
			help_for(argv0, "extract-signature");
			cmd = CMD_HELP;
			return 0; /* FAILED */
		} else if ((cmd == CMD_REMOVE) && !strcmp(*argv, "--help")) {
			help_for(argv0, "remove-signature");
			cmd = CMD_HELP;
			return 0; /* FAILED */
		} else if ((cmd == CMD_SIGN) && !strcmp(*argv, "--help")) {
			help_for(argv0, "sign");
			cmd = CMD_HELP;
			return 0; /* FAILED */
		} else if ((cmd == CMD_VERIFY) && !strcmp(*argv, "--help")) {
			help_for(argv0, "verify");
			cmd = CMD_HELP;
			return 0; /* FAILED */
		} else if (!strcmp(*argv, "-jp")) {
			char *ap;
			if (--argc < 1) {
				usage(argv0, "all");
				return 0; /* FAILED */
			}
			ap = *(++argv);
			for (i=0; ap[i]; i++) ap[i] = (char)tolower((int)ap[i]);
			if (!strcmp(ap, "low")) {
				options->jp = 0;
			} else if (!strcmp(ap, "medium")) {
				options->jp = 1;
			} else if (!strcmp(ap, "high")) {
				options->jp = 2;
			}
			if (options->jp != 0) { /* XXX */
				usage(argv0, "all");
				return 0; /* FAILED */
			}
		} else {
			failarg = *argv;
			break;
		}
	}
	if (!options->infile && argc > 0) {
		options->infile = *(argv++);
		argc--;
	}
	if (cmd != CMD_VERIFY && (!options->outfile && argc > 0)) {
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
		(cmd != CMD_VERIFY && !options->outfile) ||
		(cmd == CMD_SIGN && !((options->certfile && options->keyfile) ||
#ifndef OPENSSL_NO_ENGINE
			options->p11engine || options->p11module ||
#endif /* OPENSSL_NO_ENGINE */
			options->pkcs12file))) {
		if (failarg)
			printf("Unknown option: %s\n", failarg);
		usage(argv0, "all");
		return 0; /* FAILED */
	}
#ifndef WIN32
	if ((cmd == CMD_VERIFY || cmd == CMD_ATTACH) && access(options->cafile, R_OK)) {
		printf("Use the \"-CAfile\" option to add one or more trusted CA certificates to verify the signature.\n");
		return 0; /* FAILED */
	}
#endif /* WIN32 */
#if OPENSSL_VERSION_NUMBER>=0x30000000L
	if (cmd == CMD_SIGN && options->legacy && !use_legacy()) {
		printf("Warning: Legacy mode disabled\n");
	}
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
	return 1; /* OK */
}

int main(int argc, char **argv)
{
	TYPE_DATA *tdata = NULL;
	GLOBAL_OPTIONS options;
	int ret = -1;

	/* reset options */
	memset(&options, 0, sizeof(GLOBAL_OPTIONS));

	/* Set up OpenSSL */
	if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
		| OPENSSL_INIT_ADD_ALL_CIPHERS
		| OPENSSL_INIT_ADD_ALL_DIGESTS
		| OPENSSL_INIT_LOAD_CONFIG, NULL))
		DO_EXIT_0("Failed to init crypto\n");

	/* create some MS Authenticode OIDS we need later on */
	if (!OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL)
		|| !OBJ_create(MS_JAVA_SOMETHING, NULL, NULL)
		|| !OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL)
		|| !OBJ_create(SPC_NESTED_SIGNATURE_OBJID, NULL, NULL))
		DO_EXIT_0("Failed to create objects\n");

	/* commands and options initialization */
	if (!main_configure(argc, argv, &options))
		goto err_cleanup;
	if (!read_password(&options)) {
		printf("Failed to read password from file: %s\n", options.readpass);
		goto err_cleanup;
	}

	/* read key and certificates */
	if (options.cmd == CMD_SIGN && !read_crypto_params(&options))
		goto err_cleanup;

	tdata = file_format_msi.init(&options);
	if (!tdata)
		tdata = file_format_pe.init(&options);
	if (!tdata)
		tdata = file_format_cab.init(&options);
	/* TODO CAT files
	if (!tdata)
		tdata = file_format_cat.init(&options); */
	if (!tdata) {
		ret = 1; /* Failed */
		printf("Initialization error or unsupported input file type.\n");
		goto err_cleanup;
	}
	if (options.cmd == CMD_VERIFY) {
		ret =  tdata->format->verify_signed_file(tdata);
		goto skip_signing;
	} else if (options.cmd == CMD_EXTRACT) {
		ret = tdata->format->extract_signature(tdata);
		goto skip_signing;
	} else if (options.cmd == CMD_REMOVE) {
		ret = tdata->format->remove_signature(tdata);
		goto skip_signing;
	} else {
		ret = tdata->format->prepare_signature(tdata);
		if (ret)
			goto err_cleanup;
	}
	ret = check_timestamp_and_blob(tdata);
	if (ret)
		goto err_cleanup;

	ret = tdata->format->append_signature(tdata);
	if (ret)
		DO_EXIT_0("Append signature to outfile failed\n");

skip_signing:

	if (tdata->format->update_data_size) {
		tdata->format->update_data_size(tdata);
	}
	tdata->format->free_data(tdata);

	if (!ret && options.cmd == CMD_ATTACH) {
		ret = check_attached_data(tdata);
		if (!ret)
			printf("Signature successfully attached\n");
		/* else
		 * the new signature has been successfully appended to the outfile
		 * but only its verification failed (incorrect verification parameters?)
		 * so the output file is not deleted
		 */
	}

err_cleanup:

	if (tdata)
		tdata->format->cleanup_data(tdata);

#if OPENSSL_VERSION_NUMBER>=0x30000000L
	providers_cleanup();
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
	if (ret)
		ERR_print_errors_fp(stdout);
	if (options.cmd == CMD_HELP)
		ret = 0; /* OK */
	else
		printf(ret ? "Failed\n" : "Succeeded\n");
	free_options(&options);
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
