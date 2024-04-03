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

/*
 * Structures for Authenticode Timestamp
 */
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


ASN1_SEQUENCE(CatalogInfo) = {
    ASN1_SIMPLE(CatalogInfo, digest, ASN1_OCTET_STRING),
    ASN1_SET_OF(CatalogInfo, attributes, CatalogAuthAttr)
} ASN1_SEQUENCE_END(CatalogInfo)

IMPLEMENT_ASN1_FUNCTIONS(CatalogInfo)

ASN1_SEQUENCE(MsCtlContent) = {
    ASN1_SIMPLE(MsCtlContent, type, SpcAttributeTypeAndOptionalValue),
    ASN1_SIMPLE(MsCtlContent, identifier, ASN1_OCTET_STRING),
    ASN1_SIMPLE(MsCtlContent, time, ASN1_UTCTIME),
    ASN1_SIMPLE(MsCtlContent, version, SpcAttributeTypeAndOptionalValue),
    ASN1_SEQUENCE_OF(MsCtlContent, header_attributes, CatalogInfo),
    ASN1_OPT(MsCtlContent, filename, ASN1_ANY)
} ASN1_SEQUENCE_END(MsCtlContent)

IMPLEMENT_ASN1_FUNCTIONS(MsCtlContent)

/* Prototypes */
static ASN1_INTEGER *create_nonce(int bits);
static char *clrdp_url_get_x509(X509 *cert);
static time_t time_t_get_asn1_time(const ASN1_TIME *s);
static time_t time_t_get_si_time(PKCS7_SIGNER_INFO *si);
static ASN1_UTCTIME *asn1_time_get_si_time(PKCS7_SIGNER_INFO *si);
static time_t time_t_get_cms_time(CMS_ContentInfo *cms);
static CMS_ContentInfo *cms_get_timestamp(PKCS7_SIGNED *p7_signed,
    PKCS7_SIGNER_INFO *countersignature);
static int cursig_set_nested(PKCS7 *cursig, PKCS7 *p7);
static int nested_signatures_number_get(PKCS7 *p7);
static int X509_attribute_chain_append_object(STACK_OF(X509_ATTRIBUTE) **unauth_attr,
    u_char *p, int len, const char *oid);
static STACK_OF(PKCS7) *signature_list_create(PKCS7 *p7);
static int PKCS7_compare(const PKCS7 *const *a, const PKCS7 *const *b);
static PKCS7 *pkcs7_get_sigfile(FILE_FORMAT_CTX *ctx);
static void print_cert(X509 *cert, int i);
static int x509_store_load_crlfile(X509_STORE *store, char *cafile, char *crlfile);


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
 * Encode RFC3161 timestamp request and write it into BIO
 * [in] p7: new PKCS#7 signature
 * [in] md: message digest algorithm type
 * [returns] pointer to BIO with RFC3161 Timestamp Request
 */
static BIO *bio_encode_rfc3161_request(PKCS7 *p7, const EVP_MD *md)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    TS_MSG_IMPRINT *msg_imprint = NULL;
    ASN1_INTEGER *nonce = NULL;
    X509_ALGOR *alg = NULL;
    TS_REQ *req = NULL;
    BIO *bout = NULL, *bhash = NULL;
    u_char *p;
    int len;

    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        goto out;

    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        goto out;

    bhash = BIO_new(BIO_f_md());
    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        goto out;
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    BIO_write(bhash, si->enc_digest->data, si->enc_digest->length);
    BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));

    req = TS_REQ_new();
    if (!req)
        goto out;
    if (!TS_REQ_set_version(req, 1))
        goto out;

    msg_imprint = TS_MSG_IMPRINT_new();
    if (!msg_imprint)
        goto out;
    alg = X509_ALGOR_new();
    if (!alg)
        goto out;
    X509_ALGOR_set_md(alg, md);
    if (!X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_MD_nid(md)), V_ASN1_NULL, NULL))
        goto out;
    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, alg))
        goto out;
    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, mdbuf, EVP_MD_size(md)))
        goto out;
    if (!TS_REQ_set_msg_imprint(req, msg_imprint))
        goto out;
    /* Setting nonce */
    nonce = create_nonce(NONCE_LENGTH);
    if (!nonce)
        goto out;
    if (!TS_REQ_set_nonce(req, nonce))
        goto out;
    /* TSA is expected to include its signing certificate in the response, flag 0xFF */
    if (!TS_REQ_set_cert_req(req, 1))
        goto out;

    len = i2d_TS_REQ(req, NULL);
    p = OPENSSL_malloc((size_t)len);
    len = i2d_TS_REQ(req, &p);
    p -= len;

    bout = BIO_new(BIO_s_mem());
    BIO_write(bout, p, len);
    OPENSSL_free(p);
    (void)BIO_flush(bout);

out:
    BIO_free_all(bhash);
    ASN1_INTEGER_free(nonce);
    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(alg);
    TS_REQ_free(req);

    return bout;
}

static ASN1_INTEGER *create_nonce(int bits)
{
    unsigned char buf[20];
    ASN1_INTEGER *nonce = NULL;
    int len = (bits - 1) / 8 + 1;
    int i;

    if (len > (int)sizeof(buf)) {
        printf("Invalid nonce size\n");
        return NULL;
    }
    if (RAND_bytes(buf, len) <= 0) {
        printf("Random nonce generation failed\n");
        return NULL;
    }
    /* Find the first non-zero byte and creating ASN1_INTEGER object. */
    for (i = 0; i < len && !buf[i]; ++i) {
    }
    nonce = ASN1_INTEGER_new();
    if (!nonce) {
        printf("Could not create nonce\n");
        return NULL;
    }
    OPENSSL_free(nonce->data);
    nonce->length = len - i;
    nonce->data = OPENSSL_malloc((size_t)nonce->length + 1);
    memcpy(nonce->data, buf + i, (size_t)nonce->length);
    return nonce;
}

/*
 * Encode authenticode timestamp request and write it into BIO
 * [in] p7: new PKCS#7 signature
 * [returns] pointer to BIO with authenticode Timestamp Request
 */
static BIO *bio_encode_authenticode_request(PKCS7 *p7)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;
    TimeStampRequest *req;
    BIO *bout, *b64;
    u_char *p;
    int len;

    signer_info = PKCS7_get_signer_info(p7);
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
 * If successful the RFC 3161 timestamp will be written into
 * the PKCS7 SignerInfo structure as an unauthenticated attribute - cont[1].
 * [in, out] p7: new PKCS#7 signature
 * [in] response: RFC3161 response
 * [in] verbose: additional output mode
 * [returns] 1 on error or 0 on success
 */
static int attach_rfc3161_response(PKCS7 *p7, TS_RESP *response, int verbose)
{
    PKCS7_SIGNER_INFO *si;
    TS_STATUS_INFO *status;
    PKCS7 *token;
    u_char *p;
    int i, len;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info = PKCS7_get_signer_info(p7);

    if (!signer_info)
        return 1; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return 1; /* FAILED */
    if (!response)
        return 1; /* FAILED */

    status = TS_RESP_get_status_info(response);
    if (ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(status)) != 0) {
        if (verbose) {
            const STACK_OF(ASN1_UTF8STRING) *reasons = TS_STATUS_INFO_get0_text(status);
            printf("Timestamping failed: status %ld\n", ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(status)));
            for (i = 0; i < sk_ASN1_UTF8STRING_num(reasons); i++) {
                ASN1_UTF8STRING *reason = sk_ASN1_UTF8STRING_value(reasons, i);
                printf("%s\n", ASN1_STRING_get0_data(reason));
            }
        }
        return 1; /* FAILED */
    }
    token = TS_RESP_get_token(response);
    if (((len = i2d_PKCS7(token, NULL)) <= 0) || (p = OPENSSL_malloc((size_t)len)) == NULL) {
        if (verbose) {
            printf("Failed to convert pkcs7: %d\n", len);
            ERR_print_errors_fp(stdout);
        }
        return 1; /* FAILED */
    }
    len = i2d_PKCS7(token, &p);
    p -= len;
    if (!X509_attribute_chain_append_object(&(si->unauth_attr), p, len, SPC_RFC3161_OBJID)) {
        OPENSSL_free(p);
        return 1; /* FAILED */
    }
    OPENSSL_free(p);
    return 0; /* OK */
}

/*
 * If successful the authenticode timestamp will be written into
 * the PKCS7 SignerInfo structure as an unauthenticated attribute - cont[1]:
 * p7->d.sign->signer_info->unauth_attr
 * [in, out] p7: new PKCS#7 signature
 * [in] resp: PKCS#7 authenticode response
 * [in] verbose: additional output mode
 * [returns] 1 on error or 0 on success
 */
static int attach_authenticode_response(PKCS7 *p7, PKCS7 *resp, int verbose)
{
    PKCS7_SIGNER_INFO *info, *si;
    u_char *p;
    int len, i;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;

    if (!resp) {
        return 1; /* FAILED */
    }
    for(i = sk_X509_num(resp->d.sign->cert)-1; i>=0; i--) {
        PKCS7_add_certificate(p7, sk_X509_value(resp->d.sign->cert, i));
    }
    signer_info = PKCS7_get_signer_info(resp);
    if (!signer_info) {
        PKCS7_free(resp);
        return 1; /* FAILED */
    }
    info = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!info) {
        PKCS7_free(resp);
        return 1; /* FAILED */
    }
    if (((len = i2d_PKCS7_SIGNER_INFO(info, NULL)) <= 0) || (p = OPENSSL_malloc((size_t)len)) == NULL) {
        if (verbose) {
            printf("Failed to convert signer info: %d\n", len);
            ERR_print_errors_fp(stdout);
        }
        PKCS7_free(resp);
        return 1; /* FAILED */
    }
    len = i2d_PKCS7_SIGNER_INFO(info, &p);
    p -= len;
    PKCS7_free(resp);
    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        return 1; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return 1; /* FAILED */
    if (!X509_attribute_chain_append_object(&(si->unauth_attr), p, len, PKCS9_COUNTER_SIGNATURE)) {
        OPENSSL_free(p);
        return 1; /* FAILED */
    }
    OPENSSL_free(p);
    return 0; /* OK */
}

static void print_proxy(char *proxy)
{
    if (proxy) {
        printf ("Using configured proxy: %s\n", proxy);
    } else {
        char *http_proxy, *https_proxy;

        http_proxy = getenv("http_proxy");
        if (!http_proxy)
            http_proxy = getenv("HTTP_PROXY");
        if (http_proxy && *http_proxy != '\0')
            printf ("Using environmental HTTP proxy: %s\n", http_proxy);
        https_proxy = getenv("https_proxy");
        if (!https_proxy)
            https_proxy = getenv("HTTPS_PROXY");
        if (https_proxy && *https_proxy != '\0')
            printf ("Using environmental HTTPS proxy: %s\n", https_proxy);
    }
}

#if OPENSSL_VERSION_NUMBER<0x30000000L
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
 * Get data from HTTP server.
 * [out] http_code: HTTP status
 * [in] url: URL of the CRL distribution point or Time-Stamp Authority HTTP server
 * [in] req: timestamp request
 * [in] proxy: proxy to getting the timestamp through
 * [in] noverifypeer: do not verify the Time-Stamp Authority's SSL certificate
 * [in] verbose: additional output mode
 * [in] rfc3161: Authenticode / RFC3161 Timestamp switch
 * [returns] pointer to BIO with X509 Certificate Revocation List or timestamp response
 */
static BIO *bio_get_http_curl(long *http_code, char *url, BIO *req, char *proxy,
    int noverifypeer, int verbose, int rfc3161)
{
    CURL *curl;
    struct curl_slist *slist = NULL;
    CURLcode res;
    BIO *bin;
    u_char *p = NULL;
    long len = 0;

    if (!url) {
        return NULL; /* FAILED */
    }
    print_proxy(proxy);
    /* Start a libcurl easy session and set options for a curl easy handle */
    printf("Connecting to %s\n", url);
    curl = curl_easy_init();
    if (proxy) {
        res = curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
        if (res != CURLE_OK) {
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        }
        if (!strncmp("http:", proxy, 5)) {
            res = curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            if (res != CURLE_OK) {
                printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
            }
        }
        if (!strncmp("socks:", proxy, 6)) {
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
    if (noverifypeer) {
        res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        if (res != CURLE_OK) {
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        }
    }
    if (req) { /* POST */
        if (rfc3161) {
            /* RFC3161 Timestamp */
            slist = curl_slist_append(slist, "Content-Type: application/timestamp-query");
            slist = curl_slist_append(slist, "Accept: application/timestamp-reply");
        } else {
            /* Authenticode Timestamp */
            slist = curl_slist_append(slist, "Content-Type: application/octet-stream");
            slist = curl_slist_append(slist, "Accept: application/octet-stream");
        }
        slist = curl_slist_append(slist, "User-Agent: Transport");
        slist = curl_slist_append(slist, "Cache-Control: no-cache");
        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
        if (res != CURLE_OK) {
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        }
        len = BIO_get_mem_data(req, &p);
        res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
        if (res != CURLE_OK) {
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        }
        res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)p);
        if (res != CURLE_OK) {
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        }
        res = curl_easy_setopt(curl, CURLOPT_POST, 1);
        if (res != CURLE_OK) {
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        }
    }
    bin = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(bin, 0);
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

    if (res != CURLE_OK) {
        BIO_free_all(bin);
        if (verbose)
            printf("CURL failure: %s %s\n", curl_easy_strerror(res), url);
        curl_easy_cleanup(curl);
        return NULL; /* FAILED */
    } else {
        /* CURLE_OK (0) */
        (void)BIO_flush(bin);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    }
    /* End a libcurl easy handle */
    curl_easy_cleanup(curl);
    if (req && !rfc3161) {
        /* BASE64 encoded Authenticode Timestamp */
        BIO *b64 = BIO_new(BIO_f_base64());

        if (!blob_has_nl)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bin = BIO_push(b64, bin);
    }
    return bin;
}
#endif /* ENABLE_CURL */

#else /* OPENSSL_VERSION_NUMBER<0x30000000L */

/* HTTP callback function that supports TLS connection also via HTTPS proxy */
static BIO *http_tls_cb(BIO *bio, void *arg, int connect, int detail)
{
    HTTP_TLS_Info *info = (HTTP_TLS_Info *)arg;
    SSL_CTX *ssl_ctx = info->ssl_ctx;

    if (ssl_ctx == NULL) {
        /* not using TLS */
        return bio;
    }
    if (connect && detail) {
        /* connecting with TLS */
        SSL *ssl;
        BIO *sbio = NULL;

        if (info->use_proxy && !OSSL_HTTP_proxy_connect(bio, info->server,
            info->port, NULL, NULL, info->timeout, NULL, NULL)) {
            return NULL;
        }
        sbio = BIO_new(BIO_f_ssl());
        if (sbio == NULL) {
            return NULL;
        }
        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            BIO_free(sbio);
            return NULL;
        }
        SSL_set_tlsext_host_name(ssl, info->server);
        SSL_set_connect_state(ssl);
        BIO_set_ssl(sbio, ssl, BIO_CLOSE);
        bio = BIO_push(sbio, bio);
    }
    return bio;
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    if (!ok) {
        int error = X509_STORE_CTX_get_error(ctx);

        print_cert(X509_STORE_CTX_get_current_cert(ctx), 0);
        if (error == X509_V_ERR_UNABLE_TO_GET_CRL) {
            char *url = clrdp_url_get_x509(X509_STORE_CTX_get_current_cert(ctx));

            printf("\tWarning: Ignoring \'%s\' error for CRL validation\n",
                X509_verify_cert_error_string(error));
            printf("\nUse the \"-HTTPS-CRLfile\" option to verify CRL\n");
            if (url) {
                printf("HTTPS's CRL distribution point: %s\n", url);
                OPENSSL_free(url);
            }
            return 1;
        } else {
            printf("\tError: %s\n", X509_verify_cert_error_string(error));
        }
    }
    return ok;
}

/*
 * Read data from socket BIO
 * [in] s_bio: socket BIO
 * [in] rctx: open connection context
 * [in] use_ssl: HTTPS request switch
 * [returns] memory BIO
 */
static BIO *socket_bio_read(BIO *s_bio, OSSL_HTTP_REQ_CTX *rctx, int use_ssl)
{
    int retry = 1, ok = 0, written = 0, resp_len = 0;
    char *buf = OPENSSL_malloc(OSSL_HTTP_DEFAULT_MAX_RESP_LEN);
    BIO *resp = BIO_new(BIO_s_mem());

    if (rctx) {
        resp_len = (int)OSSL_HTTP_REQ_CTX_get_resp_len(rctx);
    }
    if (resp_len == 0) {
        int fd = (int)BIO_get_fd(s_bio, NULL);

        if (fd >= 0) {
            if (use_ssl)
                BIO_ssl_shutdown(s_bio);
            else
#ifdef WIN32
                (void)shutdown(fd, SD_SEND);
#else /* WIN32 */
                (void)shutdown(fd, SHUT_WR);
#endif /* WIN32 */
        }
    }
    ERR_clear_error();
    while (retry) {
        int n;

        errno = 0;
        n = BIO_read(s_bio, buf, OSSL_HTTP_DEFAULT_MAX_RESP_LEN);
        if (n > 0) {
            written += BIO_write(resp, buf, n);
        } else if (BIO_eof(s_bio) == 1) {
            ok = 1;
            retry = 0; /* EOF */
        } else if (BIO_should_retry(s_bio)) {
        } else {
            unsigned long err = ERR_get_error();

            if (err == 0) {
                ok = 1;
                retry = 0; /* use_ssl EOF */
            } else {
                printf("\nHTTP failure: error %ld: %s\n", err, ERR_reason_error_string(err));
                retry = 0; /* FAILED */
            }
        }
        if (resp_len > 0 && resp_len == written) {
            ok = 1;
            retry = 0; /* all response has been read */
        }
    }
    OSSL_HTTP_close(rctx, ok);
    OPENSSL_free(buf);
    if (!ok) {
        BIO_free_all(resp);
        resp = NULL;
    }

    return resp;
}

/*
 * pkcs7-signedData bytes found indicates DER form
 * in otherwise BASE64 encoded
 * '\n' newline character means BASE64 line with newline at the end
 * in otherwise BIO_FLAGS_BASE64_NO_NL flag must me set
 * [in, out] resp: memory BIO with Authenticode Timestamp data
 * [returns] none
 */
static void check_authenticode_timestamp(BIO **resp)
{
    u_char *ptr = NULL;
    const u_char pkcs7_signed[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};
    int i, len, pkcs7_signed_len, found = 0;

    len = (int)BIO_get_mem_data(*resp, &ptr);
    if (len <= 0) {
        return;
    }
    pkcs7_signed_len = (int)sizeof pkcs7_signed;
    for (i = 0; i <= len - pkcs7_signed_len; i++) {
        if (memcmp(ptr + i, pkcs7_signed, (size_t)pkcs7_signed_len) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        /* BASE64 encoded Authenticode Timestamp */
        BIO *b64 = BIO_new(BIO_f_base64());

        if (!memchr(ptr, '\n', (size_t)len)) {
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        } else {
            BIO *bio_mem = BIO_new_mem_buf(ptr, len);
            BIO_push(b64, bio_mem);
        }
        *resp = BIO_push(b64, *resp);
    }
}

/*
 * Get data from HTTP server.
 * [in] url: URL of the CRL distribution point or Time-Stamp Authority HTTP server
 * [in] req: timestamp request
 * [in] proxy: proxy to getting the timestamp through
 * [in] rfc3161: Authenticode / RFC3161 Timestamp switch
 * [in] cafile: file contains concatenated CA certificates in PEM format
 * [in] crlfile: file contains Certificate Revocation List (CRLs)
 * [returns] pointer to BIO with X509 Certificate Revocation List or timestamp response
 */
static BIO *bio_get_http(char *url, BIO *req, char *proxy, int rfc3161, char *cafile, char *crlfile)
{
    BIO *tmp_bio = NULL, *s_bio = NULL, *resp = NULL;
    OSSL_HTTP_REQ_CTX *rctx = NULL;
    int timeout = -1; /* blocking mode, exactly one try, see BIO_do_connect_retry() */
    int keep_alive = 1; /* prefer */
    int use_ssl = 0;

    if (!url) {
        return NULL; /* FAILED */
    }
    print_proxy(proxy);
    printf("Connecting to %s\n", url);

    if (!req) { /* GET */
        s_bio = OSSL_HTTP_get(url, proxy, NULL, NULL, NULL, NULL, NULL, 0, NULL,
            "application/pkix-crl", 0, OSSL_HTTP_DEFAULT_MAX_RESP_LEN, timeout);
    } else { /* POST */
        HTTP_TLS_Info info;
        SSL_CTX *ssl_ctx = NULL;
        X509_STORE *store = NULL;
        char *server = NULL;
        char *port = NULL;
        char *path = NULL;
        const char *content_type = "application/timestamp-query"; /* RFC3161 Timestamp */
        const char *expected_content_type = "application/timestamp-reply";

        if (!rfc3161) {
            u_char *p = NULL;
            long len = BIO_get_mem_data(req, &p);

            tmp_bio = BIO_new(BIO_s_mem());
            BIO_write(tmp_bio, p, (int)len);
            req = BIO_push(tmp_bio, req);
            content_type = "application/octet-stream"; /* Authenticode Timestamp */
            expected_content_type = "application/octet-stream";
        }
        if (!OSSL_HTTP_parse_url(url, &use_ssl, NULL, &server, &port, NULL, &path, NULL, NULL)) {
            return NULL; /* FAILED */
        }
        if (use_ssl) {
            ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (cafile) {
                printf("HTTPS-CAfile: %s\n", cafile);
                if (crlfile)
                    printf("HTTPS-CRLfile: %s\n", crlfile);
                store = SSL_CTX_get_cert_store(ssl_ctx);
                if (x509_store_load_crlfile(store, cafile, crlfile))
                    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
                else
                    printf("Warning: HTTPS verification was skipped\n");
            } else {
                printf("Warning: HTTPS verification was skipped\n");
            }
        }
        info.server = server;
        info.port = port;
        info.use_proxy = OSSL_HTTP_adapt_proxy(proxy, NULL, server, use_ssl) != NULL;
        info.timeout = timeout;
        info.ssl_ctx = ssl_ctx;
        s_bio = OSSL_HTTP_transfer(&rctx, server, port, path, use_ssl, proxy, NULL,
            NULL, NULL, http_tls_cb, &info, 0, NULL, content_type, req,
            expected_content_type, 0, OSSL_HTTP_DEFAULT_MAX_RESP_LEN, timeout, keep_alive);

        OPENSSL_free(server);
        OPENSSL_free(port);
        OPENSSL_free(path);
        BIO_free(tmp_bio);
        SSL_CTX_free(ssl_ctx);
    }
    if (s_bio) {
        resp = socket_bio_read(s_bio, rctx, use_ssl);
        BIO_free_all(s_bio);
        if (resp && req && !rfc3161)
            check_authenticode_timestamp(&resp);
    } else {
        printf("\nHTTP failure: Failed to get data from %s\n", url);
    }

    return resp;
}
#endif /* OPENSSL_VERSION_NUMBER<0x30000000L */

/*
 * Decode a HTTP response from BIO and write it into the PKCS7 structure
 * Add timestamp to the PKCS7 SignerInfo structure:
 * sig->d.sign->signer_info->unauth_attr
 * [in, out] p7: new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [in] url: URL of the Time-Stamp Authority server
 * [in] rfc3161: Authenticode / RFC3161 Timestamp switch
 * [returns] 1 on error or 0 on success
 */
static int add_timestamp(PKCS7 *p7, FILE_FORMAT_CTX *ctx, char *url, int rfc3161)
{
    BIO *req, *resp;
    int verbose = ctx->options->verbose || ctx->options->ntsurl == 1;
    int res = 1;
    long http_code = -1;

    /* Encode timestamp request */
    if (rfc3161) {
        req = bio_encode_rfc3161_request(p7, ctx->options->md);
    } else {
        req = bio_encode_authenticode_request(p7);
    }
    if (!req) {
        return 1; /* FAILED */
    }
#if OPENSSL_VERSION_NUMBER<0x30000000L
#ifndef ENABLE_CURL
    (void)url;
    (void)rfc3161;
    printf("Could NOT find CURL\n");
    BIO_free_all(req);
    return NULL; /* FAILED */
#else /* ENABLE_CURL */
    if (rfc3161) {
        resp = bio_get_http_curl(&http_code, url, req, ctx->options->proxy,
            ctx->options->noverifypeer, verbose, 1);
    } else {
        resp = bio_get_http_curl(&http_code, url, req, ctx->options->proxy,
            ctx->options->noverifypeer, verbose, 0);
    }
#endif /* ENABLE_CURL */
#else /* OPENSSL_VERSION_NUMBER<0x30000000L */
    if (rfc3161) {
        resp = bio_get_http(url, req, ctx->options->proxy, 1,
            ctx->options->noverifypeer ? NULL : ctx->options->https_cafile,
            ctx->options->noverifypeer ? NULL : ctx->options->https_crlfile);
    } else {
        resp = bio_get_http(url, req, ctx->options->proxy, 0,
            ctx->options->noverifypeer ? NULL : ctx->options->https_cafile,
            ctx->options->noverifypeer ? NULL : ctx->options->https_crlfile);
    }
#endif /* OPENSSL_VERSION_NUMBER<0x30000000L */
    BIO_free_all(req);
    if (resp != NULL) {
        if (rfc3161) {
            /* decode a RFC 3161 response from BIO */
            TS_RESP *response = d2i_TS_RESP_bio(resp, NULL);

            res = attach_rfc3161_response(p7, response, verbose);
            TS_RESP_free(response);
        } else {
            /* decode an authenticode response from BIO */
            PKCS7 *response = d2i_PKCS7_bio(resp, NULL);

            res = attach_authenticode_response(p7, response, verbose);
        }
        if (res && verbose) {
            if (http_code != -1) {
                printf("Failed to convert timestamp reply from %s; "
                "HTTP status %ld\n", url, http_code);
            } else {
                printf("Failed to convert timestamp reply from %s\n", url);
            }
            ERR_print_errors_fp(stdout);
        }
        BIO_free_all(resp);
    }
    return res;
}

/*
 * [in, out] p7: new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int add_timestamp_authenticode(PKCS7 *p7, FILE_FORMAT_CTX *ctx)
{
    int i;
    for (i=0; i<ctx->options->nturl; i++) {
        if (!add_timestamp(p7, ctx, ctx->options->turl[i], 0))
            return 1; /* OK */
    }
    return 0; /* FAILED */
}

/*
 * [in, out] p7: new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int add_timestamp_rfc3161(PKCS7 *p7, FILE_FORMAT_CTX *ctx)
{
    int i;
    for (i=0; i<ctx->options->ntsurl; i++) {
        if (!add_timestamp(p7, ctx, ctx->options->tsurl[i], 1))
            return 1; /* OK */
    }
    return 0; /* FAILED */
}

/*
 * [in] resp_ctx: a response context that can be used for generating responses
 * [in] data: unused
 * [returns] hexadecimal serial number
 */
static ASN1_INTEGER *serial_cb(TS_RESP_CTX *resp_ctx, void *data)
{
    int ret = 0;
    uint64_t buf;
    ASN1_INTEGER *serial = NULL;

    /* squash unused parameter warning */
    (void)data;

    if (RAND_bytes((unsigned char *)&buf, sizeof buf) <= 0) {
        printf("RAND_bytes failed\n");
        goto out;
    }
    serial = ASN1_INTEGER_new();
    if (!serial)
        goto out;
    ASN1_INTEGER_set_uint64(serial, buf);
    ret = 1;
out:
     if (!ret) {
        TS_RESP_CTX_set_status_info(resp_ctx, TS_STATUS_REJECTION,
            "Error during serial number generation.");
        TS_RESP_CTX_add_failure_info(resp_ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE);
        ASN1_INTEGER_free(serial);
        return NULL; /* FAILED */
    }
    return serial;
}

/*
 * This must return the seconds and microseconds since Jan 1, 1970 in the sec
 * and usec variables allocated by the caller.
 * [in] resp_ctx: a response context that can be used for generating responses
 * [in] data: timestamping time
 * [out] sec: total of seconds since Jan 1, 1970
 * [out] usec: microseconds (unused)
 * [returns] 0 on error or 1 on success
 */
static int time_cb(TS_RESP_CTX *resp_ctx, void *data, long *sec, long *usec)
{
    time_t *time = (time_t *)data;
    if(!*time) {
        TS_RESP_CTX_set_status_info(resp_ctx, TS_STATUS_REJECTION,
            "Time is not available.");
        TS_RESP_CTX_add_failure_info(resp_ctx, TS_INFO_TIME_NOT_AVAILABLE);
        return 0; /* FAILED */
    }
    *sec = (long int)*time;
    *usec = 0;
    return 1; /* OK */
}

/*
 * [in] ctx: structure holds input and output data
 * [in] signer_cert: the signer certificate of the TSA in PEM format
 * [in] signer_key: the private key of the TSA in PEM format
 * [in] chain: the certificate chain that will all be included in the response
 * [in] bout: timestamp request
 * [returns] RFC3161 response
 */
static TS_RESP *get_rfc3161_response(FILE_FORMAT_CTX *ctx, X509 *signer_cert,
    EVP_PKEY *signer_key, STACK_OF(X509) *chain, BIO *bout)
{
    TS_RESP_CTX *resp_ctx = NULL;
    TS_RESP *response = NULL;
    ASN1_OBJECT *policy_obj = NULL;

    resp_ctx = TS_RESP_CTX_new();
    if (!resp_ctx)
        goto out;

    TS_RESP_CTX_set_serial_cb(resp_ctx, serial_cb, NULL);
    if (!TS_RESP_CTX_set_signer_cert(resp_ctx, signer_cert)) {
        goto out;
    }
    if (!TS_RESP_CTX_set_signer_key(resp_ctx, signer_key)) {
        goto out;
    }
    if (!TS_RESP_CTX_set_certs(resp_ctx, chain)) {
        goto out;
    }
    /* message digest algorithm that the TSA accepts */
    if (!TS_RESP_CTX_add_md(resp_ctx, ctx->options->md)) {
        goto out;
    }
    /* signing digest to use */
    if (!TS_RESP_CTX_set_signer_digest(resp_ctx, ctx->options->md)) {
        goto out;
    }
    /* default policy to use when the request does not mandate any policy
     * tsa_policy1 = 1.2.3.4.1 */
    policy_obj = OBJ_txt2obj(TSA_POLICY1, 0);
    if (!policy_obj) {
        goto out;
    }
    if (!TS_RESP_CTX_set_def_policy(resp_ctx, policy_obj)) {
        goto out;
    }
    /* the accuracy of the time source of the TSA in seconds, milliseconds
     * and microseconds; e.g. secs:1, millisecs:500, microsecs:100;
     * 0 means not specified */
    if (!TS_RESP_CTX_set_accuracy(resp_ctx, 1, 500, 100)) {
        goto out;
    }
    if (ctx->options->tsa_time) {
        TS_RESP_CTX_set_time_cb(resp_ctx, time_cb, &(ctx->options->tsa_time));
    }
    /* generate RFC3161 response with embedded TS_TST_INFO structure */
    response = TS_RESP_create_response(resp_ctx, bout);
    if (!response) {
        printf("Failed to create RFC3161 response\n");
    }

out:
    ASN1_OBJECT_free(policy_obj);
    TS_RESP_CTX_free(resp_ctx);

    return response;
}

/*
 * [in] bin: certfile BIO
 * [in] certpass: NULL
 * [returns] pointer to STACK_OF(X509) structure
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

/*
 * [in, out] p7: new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] 1 on error or 0 on success
 */
static int add_timestamp_builtin(PKCS7 *p7, FILE_FORMAT_CTX *ctx)
{
    BIO *btmp, *bout;
    STACK_OF(X509) *chain;
    X509 *signer_cert = NULL;
    EVP_PKEY *signer_key;
    TS_RESP *response = NULL;
    int i, res = 1;

    btmp = BIO_new_file(ctx->options->tsa_certfile, "rb");
    if (!btmp) {
        printf("Failed to read Time-Stamp Authority certificate file: %s\n", ctx->options->tsa_certfile);
        return 0; /* FAILED */
    }
    /* .pem certificate file */
    chain = X509_chain_read_certs(btmp, NULL);
    BIO_free(btmp);
    btmp = BIO_new_file(ctx->options->tsa_keyfile, "rb");
    if (!btmp) {
        printf("Failed to read private key file: %s\n", ctx->options->tsa_keyfile);
        return 0; /* FAILED */
    }
    signer_key = PEM_read_bio_PrivateKey(btmp, NULL, NULL, NULL);
    BIO_free(btmp);
    if(!chain || !signer_key) {
        printf("Failed to load Time-Stamp Authority crypto parameters\n");
        return 0; /* FAILED */
    }
    /* find the signer's certificate located somewhere in the whole certificate chain */
    for (i=0; i<sk_X509_num(chain); i++) {
        X509 *cert = sk_X509_value(chain, i);
        if (X509_check_private_key(cert, signer_key)) {
            signer_cert = cert;
            break;
        }
    }
    if(!signer_cert) {
        printf("Failed to checking the consistency of a TSA private key with a public key in any X509 certificate\n");
        goto out;
    }

    /* The TSA signing certificate must have exactly one extended key usage
     * assigned to it: timeStamping. The extended key usage must also be critical,
     * otherwise the certificate is going to be refused. */

    /* check X509_PURPOSE_TIMESTAMP_SIGN certificate purpose */
    if (X509_check_purpose(signer_cert, X509_PURPOSE_TIMESTAMP_SIGN, 0) != 1) {
        printf("Unsupported TSA signer's certificate purpose X509_PURPOSE_TIMESTAMP_SIGN\n");
        goto out;
    }
    /* check extended key usage flag XKU_TIMESTAMP */
    if (!(X509_get_extended_key_usage(signer_cert) & XKU_TIMESTAMP)) {
        printf("Unsupported Signer's certificate purpose XKU_TIMESTAMP\n");
        goto out;
    }
    /* encode timestamp request */
    bout = bio_encode_rfc3161_request(p7, ctx->options->md);
    if (!bout) {
        printf("Failed to encode timestamp request\n");
        goto out;
    }

    response = get_rfc3161_response(ctx, signer_cert, signer_key, chain, bout);
    BIO_free_all(bout);

    if (response) {
        res = attach_rfc3161_response(p7, response, ctx->options->verbose);
        if (res) {
            printf("Failed to convert timestamp reply\n");
            ERR_print_errors_fp(stdout);
        }
    } else {
        printf("Failed to obtain RFC3161 response\n");
    }
out:
    sk_X509_pop_free(chain, X509_free);
    EVP_PKEY_free(signer_key);
    TS_RESP_free(response);
    return res;
}

/*
 * If successful the unauthenticated blob will be written into
 * the PKCS7 SignerInfo structure as an unauthenticated attribute - cont[1]:
 * p7->d.sign->signer_info->unauth_attr
 * [in, out] p7: new PKCS#7 signature
 * [returns] 0 on error or 1 on success
 */
static int add_unauthenticated_blob(PKCS7 *p7)
{
    PKCS7_SIGNER_INFO *si;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    u_char *p = NULL;
    int len = 1024+4;
    /* Length data for ASN1 attribute plus prefix */
    const char prefix[] = "\x0c\x82\x04\x00---BEGIN_BLOB---";
    const char postfix[] = "---END_BLOB---";

    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info) {
        printf("Failed to obtain PKCS#7 signer info list\n");
        return 0; /* FAILED */
    }
    si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
    if (!si)
        return 0; /* FAILED */
    if ((p = OPENSSL_malloc((size_t)len)) == NULL)
        return 0; /* FAILED */
    memset(p, 0, (size_t)len);
    memcpy(p, prefix, sizeof prefix);
    memcpy(p + len - sizeof postfix, postfix, sizeof postfix);
    if (!X509_attribute_chain_append_object(&(si->unauth_attr), p, len, SPC_UNAUTHENTICATED_DATA_BLOB_OBJID)) {
        OPENSSL_free(p);
        return 1; /* FAILED */
    }
    OPENSSL_free(p);
    return 1; /* OK */
}

/*
 * Add unauthenticated attributes (Countersignature, Unauthenticated Data Blob)
 * [in, out] p7: new PKCS#7 signature
 * [in, out] ctx: structure holds input and output data
 * [returns] 1 on error or 0 on success
 */
static int add_timestamp_and_blob(PKCS7 *p7, FILE_FORMAT_CTX *ctx)
{
    /* add counter-signature/timestamp */
    if (ctx->options->nturl && !add_timestamp_authenticode(p7, ctx)) {
        printf("%s\n%s\n", "Authenticode timestamping failed",
            "Use the \"-ts\" option to add the RFC3161 Time-Stamp Authority or choose another one Authenticode Time-Stamp Authority");
        return 1; /* FAILED */
    }
    if (ctx->options->ntsurl && !add_timestamp_rfc3161(p7, ctx)) {
        printf("%s\n%s\n", "RFC 3161 timestamping failed",
            "Use the \"-t\" option to add the Authenticode Time-Stamp Authority or choose another one RFC3161 Time-Stamp Authority");
        return 1; /* FAILED */
    }
    if (ctx->options->tsa_certfile && ctx->options->tsa_keyfile && add_timestamp_builtin(p7, ctx)) {
        printf("Built-in timestamping failed\n");
        return 1; /* FAILED */
    }
    if (ctx->options->addBlob && !add_unauthenticated_blob(p7)) {
        printf("Adding unauthenticated blob failed\n");
        return 1; /* FAILED */
    }
    return 0; /* OK */
}

/*
 * Add unauthenticated attributes to the signature at a certain position
 * [in, out] p7: new PKCS#7 signature
 * [in, out] ctx: structure holds input and output data
 * [in] index: signature index
 * [returns] 1 on error or 0 on success
 */
static int add_nested_timestamp_and_blob(PKCS7 *p7, FILE_FORMAT_CTX *ctx, int index)
{
    STACK_OF(PKCS7) *signatures;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    STACK_OF(X509_ATTRIBUTE) *unauth_attr;
    PKCS7_SIGNER_INFO *si;
    PKCS7 *p7_tmp;
    int i;

    p7_tmp = PKCS7_dup(p7);
    if (!p7_tmp) {
        return 1; /* FAILED */
    }
    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info) {
        printf("Failed to obtain PKCS#7 signer info list\n");
        return 1; /* FAILED */
    }
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si) {
        printf("Failed to obtain PKCS#7 signer info value\n");
        return 1; /* FAILED */
    }
    unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
    if (unauth_attr) {
        /* try to find and remove SPC_NESTED_SIGNATURE_OBJID attribute */
        for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
            int nid = OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID);
            X509_ATTRIBUTE *attr = X509at_get_attr(unauth_attr, i);
            if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == nid) {
                X509at_delete_attr(unauth_attr, i);
                X509_ATTRIBUTE_free(attr);
                break;
            }
        }
    }
    signatures = signature_list_create(p7_tmp);
    if (!signatures) {
        printf("Failed to create signature list\n\n");
        return 1; /* FAILED */
    }
    /* append all nested signature to the primary signature */
    for (i=1; i<sk_PKCS7_num(signatures); i++) {
        PKCS7 *sig = sk_PKCS7_value(signatures, i);
        if (i == index) {
            printf("Use the signature at index %d\n", i);
            if (add_timestamp_and_blob(sig, ctx)) {
                printf("Unable to set unauthenticated attributes\n");
                sk_PKCS7_pop_free(signatures, PKCS7_free);
                return 1; /* FAILED */
            }
        }
        if (!cursig_set_nested(p7, sig)) {
            printf("Unable to append the nested signature to the current signature\n");
            sk_PKCS7_pop_free(signatures, PKCS7_free);
            return 1; /* FAILED */
        }
    }
    sk_PKCS7_pop_free(signatures, PKCS7_free);
    return 0; /* OK */
}

/*
 * Add the new signature to the current signature as a nested signature:
 * new unauthenticated SPC_NESTED_SIGNATURE_OBJID attribute
 * [out] cursig: current PKCS#7 signature
 * [in] p7: new PKCS#7 signature
 * [in] ctx: structure holds input and output data
 * [returns] 0 on error or 1 on success
 */
static int cursig_set_nested(PKCS7 *cursig, PKCS7 *p7)
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
    if (!X509_attribute_chain_append_object(&(si->unauth_attr), p, len, SPC_NESTED_SIGNATURE_OBJID)) {
        OPENSSL_free(p);
        return 0; /* FAILED */
    }
    OPENSSL_free(p);
    return 1; /* OK */
}

/*
 * Return the number of objects in SPC_NESTED_SIGNATURE_OBJID attribute
 * [in] p7: existing PKCS#7 signature (Primary Signature)
 * [returns] -1 on error or the number of nested signatures
 */
static int nested_signatures_number_get(PKCS7 *p7)
{
    int i;
    STACK_OF(X509_ATTRIBUTE) *unauth_attr;
    PKCS7_SIGNER_INFO *si;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info = PKCS7_get_signer_info(p7);

    if (!signer_info)
        return -1; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return -1; /* FAILED */
    unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
    if (!unauth_attr)
        return 0; /* OK, no unauthenticated attributes */
    for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
        int nid = OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID);
        X509_ATTRIBUTE *attr = X509at_get_attr(unauth_attr, i);
        if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == nid) {
            /* Nested Signature - Policy OID: 1.3.6.1.4.1.311.2.4.1 */
            return X509_ATTRIBUTE_count(attr);
        }
    }
    return 0; /* OK, no SPC_NESTED_SIGNATURE_OBJID attribute */
}

/*
 * [in, out] unauth_attr: unauthenticated attributes list
 * [in] p: PKCS#7 data
 * [in] len: PKCS#7 data length
 * [in] oid: unauthenticated attribute oid: SPC_UNAUTHENTICATED_DATA_BLOB_OBJID,
        PKCS9_COUNTER_SIGNATURE, SPC_RFC3161_OBJID or SPC_NESTED_SIGNATURE_OBJID
 * [returns] 0 on error or 1 on success
 */
static int X509_attribute_chain_append_object(STACK_OF(X509_ATTRIBUTE) **unauth_attr,
    u_char *p, int len, const char *oid)
{
    X509_ATTRIBUTE *attr = NULL;
    ASN1_OBJECT *object;
    char object_txt[128];

    if (*unauth_attr == NULL) {
        if ((*unauth_attr = sk_X509_ATTRIBUTE_new_null()) == NULL)
            return 0; /* FAILED */
    } else {
        /* try to find indicated unauthenticated attribute */
        int i;
        for (i = 0; i < X509at_get_attr_count(*unauth_attr); i++) {
            attr = X509at_get_attr(*unauth_attr, i);
            object = X509_ATTRIBUTE_get0_object(attr);
            if (object == NULL)
                continue;
            object_txt[0] = 0x00;
            OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
            if ((!strcmp(oid, PKCS9_COUNTER_SIGNATURE) || !strcmp(oid, SPC_RFC3161_OBJID))
                && (!strcmp(object_txt, PKCS9_COUNTER_SIGNATURE) || !strcmp(object_txt, SPC_RFC3161_OBJID))) {
                /* free up countersignature/timestamp in unauthenticated attributes
                 * to override the previous timestamp */
                X509at_delete_attr(*unauth_attr, i);
                X509_ATTRIBUTE_free(attr);
                continue;
            }
            if (!strcmp(oid, object_txt)) {
                /* append p to the V_ASN1_SEQUENCE */
                if (!X509_ATTRIBUTE_set1_data(attr, V_ASN1_SEQUENCE, p, len))
                    return 0; /* FAILED */
                return 1; /* OK */
            }
        }
    }
    /* create new unauthenticated attribute */
    attr = X509_ATTRIBUTE_create_by_NID(NULL, OBJ_txt2nid(oid), V_ASN1_SEQUENCE, p, len);
    if (!attr)
        return 0; /* FAILED */
    if (!sk_X509_ATTRIBUTE_push(*unauth_attr, attr)) {
        X509_ATTRIBUTE_free(attr);
        return 0; /* FAILED */
    }
    return 1; /* OK */
}


/*
 * [in, out] store: structure for holding information about X.509 certificates and CRLs
 * [in] time: time_t to set
 * [returns] 0 on error or 1 on success
 */
static int x509_store_set_time(X509_STORE *store, time_t time)
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

/*
 * Check the syntax of the time structure and print the time in human readable format
 * [in] time: time structure
 * [returns] 0 on error or 1 on success
 */
static int print_asn1_time(const ASN1_TIME *time)
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

/*
 * Set the structure s to the time represented by the time_t value
 * to print this time in human readable format
 * [in] time: time_t value
 * [returns] 0 on error or 1 on success
 */
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
    ret = print_asn1_time(s);
    ASN1_TIME_free(s);
    return ret;

}

/*
 * Print certificate subject name, issuer name, serial number and expiration date
 * [in] cert: X509 certificate
 * [in] i: certificate number in order
 * [returns] none
 */
static void print_cert(X509 *cert, int i)
{
    char *subject, *issuer, *serial;
    BIGNUM *serialbn;

    if (!cert)
        return;
    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    serialbn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
    serial = BN_bn2hex(serialbn);
    printf("\t------------------\n");
    printf("\tSigner #%d:\n\t\tSubject: %s\n\t\tIssuer : %s\n\t\tSerial : %s\n\t\tCertificate expiration date:\n",
            i, subject, issuer, serial);
    printf("\t\t\tnotBefore : ");
    print_asn1_time(X509_get0_notBefore(cert));
    printf("\t\t\tnotAfter : ");
    print_asn1_time(X509_get0_notAfter(cert));
    printf("\n");

    OPENSSL_free(subject);
    OPENSSL_free(issuer);
    BN_free(serialbn);
    OPENSSL_free(serial);
}

/*
 * [in] certs: X509 certificate chain
 * [returns] none
 */
static void print_certs_chain(STACK_OF(X509) *certs)
{
    int i;

    for (i=0; i<sk_X509_num(certs); i++) {
        print_cert(sk_X509_value(certs, i), i);
    }
}

/*
 * [in] txt, list
 * [returns] 0 on error or 1 on success
 */
static int on_list(const char *txt, const char *list[])
{
    while (*list)
        if (!strcmp(txt, *list++))
            return 1; /* OK */
    return 0; /* FAILED */
}

/*
 * Check Windows certificate whitelist:
 * https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/trusted-root-certificates-are-required
 * For Microsoft Root Authority, serial number: 00C1008B3C3C8811D13EF663ECDF40,
 * fingerprint: "F3:84:06:E5:40:D7:A9:D9:0C:B4:A9:47:92:99:64:0F:FB:6D:F9:E2:24:EC:C7:A0:1C:0D:95:58:D8:DA:D7:7D"
 * expiration date: 12/31/2020, intended purposes: All,
 * ignore X509_V_ERR_INVALID_CA and X509_V_ERR_CERT_HAS_EXPIRED
 * [in] cert: X509 certificate
 * [in] error: error code
 * [returns] 0 on error or 1 on success
 */
static int trusted_cert(X509 *cert, int error) {
    const char *fingerprints[] = {
        "F3:84:06:E5:40:D7:A9:D9:0C:B4:A9:47:92:99:64:0F:FB:6D:F9:E2:24:EC:C7:A0:1C:0D:95:58:D8:DA:D7:7D",
        NULL
    };
    u_char mdbuf[EVP_MAX_MD_SIZE], *p;
    char *hex = NULL;
    int len;
    const EVP_MD *md = EVP_get_digestbynid(NID_sha256);
    BIO *bhash = BIO_new(BIO_f_md());

    if (!BIO_set_md(bhash, md)) {
        BIO_free_all(bhash);
        return 0; /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    len = i2d_X509(cert, NULL);
    p = OPENSSL_malloc((size_t)len);
    i2d_X509(cert, &p);
    p -= len;
    BIO_write(bhash, p, len);
    OPENSSL_free(p);
    BIO_gets(bhash, (char *)mdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);

    hex = OPENSSL_buf2hexstr(mdbuf, (long)EVP_MD_size(md));
    if (!hex) {
        return 0; /* FAILED */
    }
    if (on_list(hex, fingerprints)) {
        printf("\tWarning: Ignoring \'%s\' error for Windows certificate whitelist\n",
            X509_verify_cert_error_string(error));
        OPENSSL_free(hex);
        return 1; /* trusted */
    }
    OPENSSL_free(hex);
    return 0; /* untrusted */
}

/*
 * X509_STORE_CTX_verify_cb
 */
static int verify_ca_callback(int ok, X509_STORE_CTX *ctx)
{
    int error = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    print_cert(current_cert, depth);
    if (!ok) {
        if (trusted_cert(current_cert, error)) {
            return 1;
        } else if (error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            printf("\tError: Unable to get local CA certificate; %s\n",
                X509_verify_cert_error_string(error));
        } else {
            printf("\tError: %s\n", X509_verify_cert_error_string(error));
        }
    }
    return ok;
}

static int verify_crl_callback(int ok, X509_STORE_CTX *ctx)
{
    int error = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    print_cert(current_cert, depth);
    if (!ok) {
        if (trusted_cert(current_cert, error)) {
            return 1;
        } else if (error == X509_V_ERR_CERT_HAS_EXPIRED) {
            printf("\tWarning: Ignoring \'%s\' error for CRL validation\n",
                X509_verify_cert_error_string(error));
            return 1;
        } else if (error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            printf("\tError: Unable to get local CA certificate; %s\n",
                X509_verify_cert_error_string(error));
        }
         else {
            printf("\tError: %s\n", X509_verify_cert_error_string(error));
        }
    }
    return ok;
}

/*
 * [in, out] store: structure for holding information about X.509 certificates and CRLs
 * [in] cafile: file contains concatenated CA certificates in PEM format
 * [returns] 0 on error or 1 on success
 */
static int x509_store_load_file(X509_STORE *store, char *cafile)
{
    X509_LOOKUP *lookup;
    X509_VERIFY_PARAM *param;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup || !cafile)
        return 0; /* FAILED */
    if (!X509_LOOKUP_load_file(lookup, cafile, X509_FILETYPE_PEM)) {
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
    X509_STORE_set_verify_cb(store, verify_ca_callback);

    return 1; /* OK */
}

/*
 * [in, out] store: structure for holding information about X.509 certificates and CRLs
 * [in] cafile: file contains concatenated CA certificates in PEM format
 * [in] crlfile: file contains Certificate Revocation List (CRLs)
 * [returns] 0 on error or 1 on success
 */
static int x509_store_load_crlfile(X509_STORE *store, char *cafile, char *crlfile)
{
    X509_LOOKUP *lookup;
    X509_VERIFY_PARAM *param;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup)
        return 0; /* FAILED */
    if (!X509_LOOKUP_load_file(lookup, cafile, X509_FILETYPE_PEM)) {
        printf("\nError: no certificate found\n");
        return 0; /* FAILED */
    }
    if (crlfile && !X509_load_crl_file(lookup, crlfile, X509_FILETYPE_PEM)) {
        printf("\nError: no CRL found in %s\n", crlfile);
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
    X509_STORE_set_verify_cb(store, verify_crl_callback);

    return 1; /* OK */
}

/*
 * Initialise X509_STORE_CTX structure to discover and validate a certificate chain
 * based on given parameters
 * [in] cafile: file contains concatenated CA certificates in PEM format
 * [in] crlfile: file contains Certificate Revocation List (CRLs)
 * [in] crls: additional CRLs obtained from p7->d.sign->crl
 * [in] signer: signer's X509 certificate
 * [in] chain: list of additional certificates which will be untrusted but be used to build the chain
 * [returns] 0 on error or 1 on success
 */
static int verify_crl(char *cafile, char *crlfile, STACK_OF(X509_CRL) *crls,
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
    if (!x509_store_load_crlfile(store, cafile, crlfile))
        goto out;

    /* initialise an X509_STORE_CTX structure for subsequent use by X509_verify_cert()*/
    if (!X509_STORE_CTX_init(ctx, store, signer, chain))
        goto out;

    /* set an additional CRLs */
    if (crls)
        X509_STORE_CTX_set0_crls(ctx, crls);

    printf("\nCertificate Revocation List verified using:\n");
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
 * [in] cert: X509 certificate
 * [returns] CRL distribution point url
 */
static char *clrdp_url_get_x509(X509 *cert)
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

/*
 * Get Certificate Revocation List from a CRL distribution point
 * and write it into the X509_CRL structure.
 * [in] proxy: proxy to getting CRL through
 * [in] url: URL of the CRL distribution point server
 * [returns] X509 Certificate Revocation List
 */
static X509_CRL *x509_crl_get(char *proxy, char *url)
{
    X509_CRL *crl;
    BIO *bio = NULL;

#if OPENSSL_VERSION_NUMBER<0x30000000L
#ifndef ENABLE_CURL
    printf("Could NOT find CURL\n");
    return NULL; /* FAILED */
#else /* ENABLE_CURL */
    long http_code = -1;
    bio = bio_get_http_curl(&http_code, url, NULL, proxy, 0, 1, 0);
#endif /* ENABLE_CURL */
#else /* OPENSSL_VERSION_NUMBER<0x30000000L */
    bio = bio_get_http(url, NULL, proxy, 0, NULL, NULL);
#endif /* OPENSSL_VERSION_NUMBER<0x30000000L */
    if (!bio) {
        printf("Warning: Faild to get CRL from %s\n\n", url);
        return NULL; /* FAILED */
    }
    crl = d2i_X509_CRL_bio(bio, NULL);  /* DER format */
    if (!crl) {
        (void)BIO_seek(bio, 0);
        crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL); /* PEM format */
    }
    BIO_free_all(bio);
    if (!crl) {
         printf("Warning: Faild to decode CRL from %s\n\n", url);
         return NULL; /* FAILED */
    }
    return crl; /* OK */
}

/*
 * Create CRLs from p7->d.sign->crl and x509_CRL (from CRL distribution point).
 * [in] p7: PKCS#7 signature
 * [in] crl: X509 Certificate Revocation List
 * [returns] X509 Certificate Revocation Lists (CRLs)
 */
static STACK_OF(X509_CRL) *x509_crl_list_get(PKCS7 *p7, X509_CRL *crl)
{
    int i;
    STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();

    for (i = 0; i < sk_X509_CRL_num(p7->d.sign->crl); i++) {
        if (!sk_X509_CRL_push(crls, sk_X509_CRL_value(p7->d.sign->crl, i))) {
            sk_X509_CRL_pop_free(crls, X509_CRL_free);
            return NULL;
        }
    }
    if (crl && !sk_X509_CRL_push(crls, crl)) {
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        X509_CRL_free(crl);
        return NULL;
    }
    return crls;
}

static void print_timestamp_serial_number(TS_TST_INFO *token)
{
    BIGNUM *serialbn;
    char *number;

    if (!token)
        return;
    serialbn = ASN1_INTEGER_to_BN(TS_TST_INFO_get_serial(token), NULL);
    number = BN_bn2hex(serialbn);
    printf("Timestamp serial number: %s\n", number);
    BN_free(serialbn);
    OPENSSL_free(number);
}

/*
 * Compare the hash provided from the TSTInfo object against the hash computed
 * from the signature created by the signing certificate's private key
 * [in] p7: PKCS#7 signature
 * [in] timestamp: CMS_ContentInfo struct for Authenticode Timestamp or RFC 3161 Timestamp
 * [returns] 0 on error or 1 on success
 */
static int verify_timestamp_token(PKCS7 *p7, CMS_ContentInfo *timestamp)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;
    ASN1_OCTET_STRING **pos;

    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        return 0; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return 0; /* FAILED */

    /* get the embedded content */
    pos  = CMS_get0_content(timestamp);
    if (pos != NULL && *pos != NULL) {
        const u_char *p = (*pos)->data;
        TS_TST_INFO *token = d2i_TS_TST_INFO(NULL, &p, (*pos)->length);

        if (token) {
            BIO *bhash;
            u_char mdbuf[EVP_MAX_MD_SIZE];
            ASN1_OCTET_STRING *hash;
            const ASN1_OBJECT *aoid;
            int md_nid;
            const EVP_MD *md;
            TS_MSG_IMPRINT *msg_imprint = TS_TST_INFO_get_msg_imprint(token);
            const X509_ALGOR *alg = TS_MSG_IMPRINT_get_algo(msg_imprint);

            X509_ALGOR_get0(&aoid, NULL, NULL, alg);
            md_nid = OBJ_obj2nid(aoid);
            md = EVP_get_digestbynid(md_nid);

            /* compute a hash from the encrypted message digest value of the file */
            bhash = BIO_new(BIO_f_md());
            if (!BIO_set_md(bhash, md)) {
                printf("Unable to set the message digest of BIO\n");
                BIO_free_all(bhash);
                TS_TST_INFO_free(token);
                return 0; /* FAILED */
            }
            BIO_push(bhash, BIO_new(BIO_s_null()));
            BIO_write(bhash, si->enc_digest->data, si->enc_digest->length);
            BIO_gets(bhash, (char*)mdbuf, EVP_MD_size(md));
            BIO_free_all(bhash);

            /* compare the provided hash against the computed hash */
            hash =TS_MSG_IMPRINT_get_msg(msg_imprint);
            if (memcmp(mdbuf, hash->data, (size_t)hash->length)) {
                printf("Hash value mismatch:\n\tMessage digest algorithm: %s\n",
                        (md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_nid));
                print_hash("\tComputed message digest", "", mdbuf, EVP_MD_size(md));
                print_hash("\tReceived message digest", "", hash->data, hash->length);
                printf("\nFile's message digest verification: failed\n");
                TS_TST_INFO_free(token);
                return 0; /* FAILED */
            } /* else Computed and received message digests matched */

            print_timestamp_serial_number(token);
            TS_TST_INFO_free(token);
        } else
            /* our CMS_ContentInfo struct created for Authenticode Timestamp
             * does not contain any TS_TST_INFO struct as specified in RFC 3161 */
            ERR_clear_error();
    }

    return 1; /* OK */
}

/*
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [in] timestamp: CMS_ContentInfo struct for Authenticode Timestamp or RFC 3161 Timestamp
 * [in] time: timestamp verification time
 * [returns] 0 on error or 1 on success
 */
static int verify_timestamp(FILE_FORMAT_CTX *ctx, PKCS7 *p7, CMS_ContentInfo *timestamp, time_t time)
{
    X509_STORE *store;
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *cmssi;
    X509 *signer;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    char *url;
    int verok = 0;

    store = X509_STORE_new();
    if (!store)
        goto out;
    if (x509_store_load_file(store, ctx->options->tsa_cafile)) {
        /*
         * The TSA signing key MUST be of a sufficient length to allow for a sufficiently
         * long lifetime.  Even if this is done, the key will  have a finite lifetime.
         * Thus, any token signed by the TSA SHOULD  be time-stamped again or notarized
         * at a later date to renew the trust that exists in the TSA's signature.
         * https://datatracker.ietf.org/doc/html/rfc3161#section-4
         * Signtool does not respect this RFC and neither we do.
         * So verify timestamp against the time of its creation.
         */
        if (!x509_store_set_time(store, time)) {
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
    printf("\nTimestamp verified using:\n");
    if (!CMS_verify(timestamp, NULL, store, 0, NULL, 0)) {
        STACK_OF(X509) *cms_certs;

        printf("\nCMS_verify error\n");
        X509_STORE_free(store);
        printf("\nFailed timestamp certificate chain retrieved from the signature:\n");
        cms_certs = CMS_get1_certs(timestamp);
        print_certs_chain(cms_certs);
        sk_X509_pop_free(cms_certs, X509_free);
        goto out;
    }
    X509_STORE_free(store);

    sinfos = CMS_get0_SignerInfos(timestamp);
    cmssi = sk_CMS_SignerInfo_value(sinfos, 0);
    CMS_SignerInfo_get0_algs(cmssi, NULL, &signer, NULL, NULL);

    /* verify a Certificate Revocation List */
    url = clrdp_url_get_x509(signer);
    if (url) {
        if (ctx->options->ignore_cdp) {
            printf("Ignored TSA's CRL distribution point: %s\n", url);
        } else {
            printf("TSA's CRL distribution point: %s\n", url);
            crl = x509_crl_get(ctx->options->proxy, url);
        }
        OPENSSL_free(url);
        if (!crl && !ctx->options->tsa_crlfile) {
            printf("Use the \"-TSA-CRLfile\" option to add one or more Time-Stamp Authority CRLs in PEM format.\n");
            goto out;
        }
    }
    if (p7->d.sign->crl || crl) {
        crls = x509_crl_list_get(p7, crl);
        if (!crls) {
            printf("Failed to use CRL distribution point\n");
            goto out;
        }
    }
    if (ctx->options->tsa_crlfile || crls) {
        STACK_OF(X509) *chain = CMS_get1_certs(timestamp);
        int crlok = verify_crl(ctx->options->tsa_cafile, ctx->options->tsa_crlfile,
            crls, signer, chain);
        sk_X509_pop_free(chain, X509_free);
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        printf("Timestamp Server Signature CRL verification: %s\n", crlok ? "ok" : "failed");
        if (!crlok)
            goto out;
    } else {
        printf("\n");
    }
    /* check extended key usage flag XKU_TIMESTAMP */
    if (!(X509_get_extended_key_usage(signer) & XKU_TIMESTAMP)) {
        printf("Unsupported Signer's certificate purpose XKU_TIMESTAMP\n");
        goto out;
    }
    /* verify the hash provided from the trusted timestamp */
    if (!verify_timestamp_token(p7, timestamp)) {
        goto out;
    }
    verok = 1; /* OK */
out:
    if (!verok)
        ERR_print_errors_fp(stdout);
    return verok;
}

#if OPENSSL_VERSION_NUMBER<0x30000000L
static int PKCS7_type_is_other(PKCS7 *p7)
{
    int isOther = 1;
    int nid = OBJ_obj2nid(p7->type);

    switch (nid) {
    case NID_pkcs7_data:
    case NID_pkcs7_signed:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_signedAndEnveloped:
    case NID_pkcs7_digest:
    case NID_pkcs7_encrypted:
        isOther = 0;
        break;
    default:
        isOther = 1;
    }
    return isOther;
}
#endif /* OPENSSL_VERSION_NUMBER<0x30000000L */

/*
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [in] time: signature verification time
 * [in] signer: signer's X509 certificate
 * [returns] 1 on error or 0 on success
 */
static int verify_authenticode(FILE_FORMAT_CTX *ctx, PKCS7 *p7, time_t time, X509 *signer)
{
    X509_STORE *store;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    BIO *bio = NULL;
    int verok = 0;
    char *url;
    PKCS7 *contents = p7->d.sign->contents;

    store = X509_STORE_new();
    if (!store)
        goto out;

    if (!x509_store_load_file(store, ctx->options->cafile)) {
        printf("Failed to add store lookup file\n");
        X509_STORE_free(store);
        goto out;
    }
    if (time != INVALID_TIME) {
        printf("Signature verification time: ");
        print_time_t(time);
        if (!x509_store_set_time(store, time)) {
            printf("Failed to set signature time\n");
            X509_STORE_free(store);
            goto out;
        }
    } else if (ctx->options->time != INVALID_TIME) {
        printf("Signature verification time: ");
        print_time_t(ctx->options->time);
        if (!x509_store_set_time(store, ctx->options->time)) {
            printf("Failed to set verifying time\n");
            X509_STORE_free(store);
            goto out;
        }
    }
    /* verify a PKCS#7 signedData structure */
    if (PKCS7_type_is_other(contents) && (contents->d.other != NULL)
        && (contents->d.other->value.sequence != NULL)
        && (contents->d.other->value.sequence->length > 0)) {
        if (contents->d.other->type == V_ASN1_SEQUENCE) {
            /* only verify the content of the sequence */
            const unsigned char *data = contents->d.other->value.sequence->data;
            long len;
            int inf, tag, class;

            inf = ASN1_get_object(&data, &len, &tag, &class,
                contents->d.other->value.sequence->length);
            if (inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE) {
                printf("Corrupted data content\n");
                X509_STORE_free(store);
                goto out;
            }
            bio = BIO_new_mem_buf(data, (int)len);
        } else {
            /* verify the entire value */
            bio = BIO_new_mem_buf(contents->d.other->value.sequence->data,
                contents->d.other->value.sequence->length);
        }
    } else {
        printf("Corrupted data content\n");
        X509_STORE_free(store);
        goto out;
    }
    printf("Signing certificate chain verified using:\n");
    /*
     * In the PKCS7_verify() function, the BIO *indata parameter refers to
     * the signed data if the content is detached from p7.
     * Otherwise, indata should be NULL, and then the signed data must be in p7.
     * The OpenSSL error workaround is to put the inner content into BIO *indata parameter
     * https://github.com/openssl/openssl/pull/22575
     */
    if (!PKCS7_verify(p7, NULL, store, bio, NULL, 0)) {
        printf("\nPKCS7_verify error\n");
        X509_STORE_free(store);
        BIO_free(bio);
        printf("\nFailed signing certificate chain retrieved from the signature:\n");
        print_certs_chain(p7->d.sign->cert);
        goto out;
    }
    X509_STORE_free(store);
    BIO_free(bio);

    /* verify a Certificate Revocation List */
    url = clrdp_url_get_x509(signer);
    if (url) {
        if (ctx->options->ignore_cdp) {
            printf("Ignored CRL distribution point: %s\n", url);
        } else {
            printf("CRL distribution point: %s\n", url);
            crl = x509_crl_get(ctx->options->proxy, url);
        }
        OPENSSL_free(url);
        if (!crl && !ctx->options->crlfile) {
            printf("Use the \"-CRLfile\" option to add one or more CRLs in PEM format.\n");
            goto out;
        }
    }
    if (p7->d.sign->crl || crl) {
        crls = x509_crl_list_get(p7, crl);
        if (!crls) {
            printf("Failed to use CRL distribution point\n");
            goto out;
        }
    }
    if (ctx->options->crlfile || crls) {
        STACK_OF(X509) *chain = p7->d.sign->cert;
        int crlok = verify_crl(ctx->options->cafile, ctx->options->crlfile,
            crls, signer, chain);
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
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
 * [in] leafhash: optional hash algorithm and the signer's certificate hash
 * [in] cert: signer's x509 certificate
 * [returns] 0 on error or 1 on success
 */
static int verify_leaf_hash(X509 *cert, const char *leafhash)
{
    u_char *mdbuf = NULL, *certbuf, *tmp;
    u_char cmdbuf[EVP_MAX_MD_SIZE];
    const EVP_MD *md;
    long mdlen = 0;
    size_t certlen, written;
    BIO *bhash;

    /* decode the provided hash */
    char *mdid = OPENSSL_strdup(leafhash);
    char *hash = strchr(mdid, ':');
    if (hash == NULL) {
        printf("\nUnable to parse -require-leaf-hash parameter: %s\n", leafhash);
        OPENSSL_free(mdid);
        return 0; /* FAILED */
    }
    *hash++ = '\0';
    md = EVP_get_digestbyname(mdid);
    if (md == NULL) {
        printf("\nUnable to lookup digest by name '%s'\n", mdid);
        OPENSSL_free(mdid);
        return 0; /* FAILED */
    }
    mdbuf = OPENSSL_hexstr2buf(hash, &mdlen);
    if (mdlen != EVP_MD_size(md)) {
        printf("\nHash length mismatch: '%s' digest must be %d bytes long (got %ld bytes)\n",
            mdid, EVP_MD_size(md), mdlen);
        OPENSSL_free(mdid);
        OPENSSL_free(mdbuf);
        return 0; /* FAILED */
    }
    OPENSSL_free(mdid);

    /* compute the leaf certificate hash */
    bhash = BIO_new(BIO_f_md());
    if (!BIO_set_md(bhash, md)) {
        printf("Unable to set the message digest of BIO\n");
        BIO_free_all(bhash);
        OPENSSL_free(mdbuf);
        return 0; /* FAILED */
    }
    BIO_push(bhash, BIO_new(BIO_s_null()));
    certlen = (size_t)i2d_X509(cert, NULL);
    certbuf = OPENSSL_malloc(certlen);
    tmp = certbuf;
    i2d_X509(cert, &tmp);
    if (!BIO_write_ex(bhash, certbuf, certlen, &written) || written != certlen) {
        BIO_free_all(bhash);
        OPENSSL_free(mdbuf);
        OPENSSL_free(certbuf);
        return 0; /* FAILED */
    }
    BIO_gets(bhash, (char*)cmdbuf, EVP_MD_size(md));
    BIO_free_all(bhash);
    OPENSSL_free(certbuf);

    /* compare the provided hash against the computed hash */
    if (memcmp(mdbuf, cmdbuf, (size_t)EVP_MD_size(md))) {
        print_hash("\nLeaf hash value mismatch", "computed", cmdbuf, EVP_MD_size(md));
        OPENSSL_free(mdbuf);
        return 0; /* FAILED */
    }
    OPENSSL_free(mdbuf);
    return 1; /* OK */
}

/*
 * [in] timestamp: CMS_ContentInfo struct for Authenticode Timestamp or RFC 3161 Timestamp
 * [in] time: timestamp verification time
 * [returns] 0 on error or 1 on success
 */
static int print_cms_timestamp(CMS_ContentInfo *timestamp, time_t time)
{
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *si;
    X509_ATTRIBUTE *attr;
    int md_nid;
    ASN1_INTEGER *serialno;
    char *issuer_name, *serial;
    BIGNUM *serialbn;
    X509_ALGOR *pdig;
    X509_NAME *issuer = NULL;

    sinfos = CMS_get0_SignerInfos(timestamp);
    if (sinfos == NULL)
        return 0; /* FAILED */
    si = sk_CMS_SignerInfo_value(sinfos, 0);
    if (si == NULL)
        return 0; /* FAILED */
    printf("\nCountersignatures:\n\tTimestamp time: ");
    print_time_t(time);

    /* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
    attr = CMS_signed_get_attr(si, CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1));
    printf("\tSigning time: ");
    print_time_t(time_t_get_asn1_time(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL)));

    CMS_SignerInfo_get0_algs(si, NULL, NULL, &pdig, NULL);
    if (pdig == NULL || pdig->algorithm == NULL)
        return 0; /* FAILED */
    md_nid = OBJ_obj2nid(pdig->algorithm);
    printf("\tHash Algorithm: %s\n", (md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_nid));

    if (!CMS_SignerInfo_get0_signer_id(si, NULL, &issuer, &serialno) || !issuer)
        return 0; /* FAILED */
    issuer_name = X509_NAME_oneline(issuer, NULL, 0);
    serialbn = ASN1_INTEGER_to_BN(serialno, NULL);
    serial = BN_bn2hex(serialbn);
    printf("\tIssuer: %s\n\tSerial: %s\n", issuer_name, serial);
    OPENSSL_free(issuer_name);
    BN_free(serialbn);
    OPENSSL_free(serial);
    return 1; /* OK */
}

/*
 * RFC3852: the message-digest authenticated attribute type MUST be
 * present when there are any authenticated attributes present
 * [in] timestamp: CMS_ContentInfo struct for Authenticode Timestamp or RFC 3161 Timestamp
 * [in] p7: PKCS#7 signature
 * [in] verbose: additional output mode
 * [returns] 0 on error or 1 on success
 */
static time_t time_t_timestamp_get_attributes(CMS_ContentInfo **timestamp, PKCS7 *p7, int verbose)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;
    int md_nid, i;
    STACK_OF(X509_ATTRIBUTE) *auth_attr, *unauth_attr;
    X509_ATTRIBUTE *attr;
    ASN1_OBJECT *object;
    ASN1_STRING *value;
    char object_txt[128];
    time_t time = INVALID_TIME;

    signer_info = PKCS7_get_signer_info(p7);
    if (!signer_info)
        return INVALID_TIME; /* FAILED */
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        return INVALID_TIME; /* FAILED */
    md_nid = OBJ_obj2nid(si->digest_alg->algorithm);
    printf("Message digest algorithm: %s\n",
        (md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2sn(md_nid));

    /* Unauthenticated attributes */
    auth_attr = PKCS7_get_signed_attributes(si); /* cont[0] */
    printf("\nAuthenticated attributes:\n");
    for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
        attr = X509at_get_attr(auth_attr, i);
        object = X509_ATTRIBUTE_get0_object(attr);
        if (object == NULL)
            continue;
        object_txt[0] = 0x00;
        OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
        if (!strcmp(object_txt, PKCS9_MESSAGE_DIGEST)) {
            /* PKCS#9 message digest - Policy OID: 1.2.840.113549.1.9.4 */
            const u_char *mdbuf;
            int len;
            ASN1_STRING *digest  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_OCTET_STRING, NULL);
            if (digest == NULL)
                continue;
            mdbuf = ASN1_STRING_get0_data(digest);
            len = ASN1_STRING_length(digest);
            print_hash("\tMessage digest", "", mdbuf, len);
        } else if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
            /* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
            ASN1_UTCTIME *signtime = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
            if (signtime == NULL)
                continue;
            printf("\tSigning time: ");
            print_time_t(time_t_get_asn1_time(signtime));
        } else if (!strcmp(object_txt, SPC_SP_OPUS_INFO_OBJID)) {
            /* Microsoft OID: 1.3.6.1.4.1.311.2.1.12 */
            SpcSpOpusInfo *opus;
            const u_char *data;
            value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
            if (value == NULL)
                continue;
            data = ASN1_STRING_get0_data(value);
            opus = d2i_SpcSpOpusInfo(NULL, &data, ASN1_STRING_length(value));
            if (opus == NULL)
                continue;
            if (opus->moreInfo && opus->moreInfo->type == 0) {
                char *url = OPENSSL_strdup((char *)opus->moreInfo->value.url->data);
                printf("\tURL description: %s\n", url);
                OPENSSL_free(url);
            }
            if (opus->programName) {
                char *desc = NULL;
                if (opus->programName->type == 0) {
                    u_char *opusdata;
                    int len = ASN1_STRING_to_UTF8(&opusdata, opus->programName->value.unicode);
                    if (len >= 0) {
                        desc = OPENSSL_strndup((char *)opusdata, (size_t)len);
                        OPENSSL_free(opusdata);
                    }
                } else {
                    desc = OPENSSL_strdup((char *)opus->programName->value.ascii->data);
                }
                if (desc) {
                    printf("\tText description: %s\n", desc);
                    OPENSSL_free(desc);
                }
            }
            SpcSpOpusInfo_free(opus);
        } else if (!strcmp(object_txt, SPC_STATEMENT_TYPE_OBJID)) {
            /* Microsoft OID: 1.3.6.1.4.1.311.2.1.11 */
            const u_char *purpose;
            value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
            if (value == NULL)
                continue;
            purpose = ASN1_STRING_get0_data(value);
            if (!memcmp(purpose, purpose_comm, sizeof purpose_comm))
                printf("\tMicrosoft Commercial Code Signing purpose\n");
            else if (!memcmp(purpose, purpose_ind, sizeof purpose_ind))
                printf("\tMicrosoft Individual Code Signing purpose\n");
            else
                printf("\tUnrecognized Code Signing purpose\n");
        } else if (!strcmp(object_txt, MS_JAVA_SOMETHING)) {
            /* Microsoft OID: 1.3.6.1.4.1.311.15.1 */
            const u_char *level;
            value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
            if (value == NULL)
                continue;
            level = ASN1_STRING_get0_data(value);
            if (!memcmp(level, java_attrs_low, sizeof java_attrs_low))
                printf("\tLow level of permissions in Microsoft Internet Explorer 4.x for CAB files\n");
            else
                printf("\tUnrecognized level of permissions in Microsoft Internet Explorer 4.x for CAB files\n");
        } else if (!strcmp(object_txt, PKCS9_SEQUENCE_NUMBER)) {
            /* PKCS#9 sequence number - Policy OID: 1.2.840.113549.1.9.25.4 */
            ASN1_INTEGER *number = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_INTEGER, NULL);
            if (number == NULL)
                continue;
            printf("\tSequence number: %ld\n", ASN1_INTEGER_get(number));
         }
    }

    /* Unauthenticated attributes */
    unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
    for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
        attr = X509at_get_attr(unauth_attr, i);
        object = X509_ATTRIBUTE_get0_object(attr);
        if (object == NULL)
            continue;
        object_txt[0] = 0x00;
        OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
        if (!strcmp(object_txt, PKCS9_COUNTER_SIGNATURE)) {
            /* Authenticode Timestamp - Policy OID: 1.2.840.113549.1.9.6 */
            const u_char *data;
            CMS_ContentInfo *cms;
            PKCS7_SIGNER_INFO *countersi;
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
            time = time_t_get_si_time(countersi);
            if (time != INVALID_TIME) {
                cms = cms_get_timestamp(p7->d.sign, countersi);
                if (cms) {
                    if (!print_cms_timestamp(cms, time)) {
                        CMS_ContentInfo_free(cms);
                        return INVALID_TIME; /* FAILED */
                    }
                    *timestamp = cms;
                } else {
                    printf("Error: Corrupt Authenticode Timestamp embedded content\n");
                }
            } else {
                printf("Error: PKCS9_TIMESTAMP_SIGNING_TIME attribute not found\n");
                PKCS7_SIGNER_INFO_free(countersi);
            }
        } else if (!strcmp(object_txt, SPC_RFC3161_OBJID)) {
            /* RFC3161 Timestamp - Policy OID: 1.3.6.1.4.1.311.3.3.1 */
            const u_char *data;
            CMS_ContentInfo *cms;
            value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
            if (value == NULL)
                continue;
            data = ASN1_STRING_get0_data(value);
            cms = d2i_CMS_ContentInfo(NULL, &data, ASN1_STRING_length(value));
            if (cms == NULL) {
                printf("Error: RFC3161 Timestamp could not be decoded correctly\n");
                ERR_print_errors_fp(stdout);
                continue;
            }
            time = time_t_get_cms_time(cms);
            if (time != INVALID_TIME) {
                if (!print_cms_timestamp(cms, time)) {
                    CMS_ContentInfo_free(cms);
                    return INVALID_TIME; /* FAILED */
                }
                *timestamp = cms;
            } else {
                printf("Error: Corrupt RFC3161 Timestamp embedded content\n");
                CMS_ContentInfo_free(cms);
                ERR_print_errors_fp(stdout);
            }
        } else if (!strcmp(object_txt, SPC_UNAUTHENTICATED_DATA_BLOB_OBJID)) {
            /* Unauthenticated Data Blob - Policy OID: 1.3.6.1.4.1.42921.1.2.1 */
            ASN1_STRING *blob = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTF8STRING, NULL);
            if (blob == NULL) {
                printf("Error: Unauthenticated Data Blob could not be decoded correctly\n");
                continue;
            }
            if (verbose) {
                char *data_blob = OPENSSL_buf2hexstr(blob->data, blob->length);
                printf("\nUnauthenticated Data Blob:\n%s\n", data_blob);
                OPENSSL_free(data_blob);
            } else {
                printf("\nUnauthenticated Data Blob length: %d bytes\n", blob->length);
            }
        }
    }
    return time;
}

/*
 * Convert ASN1_TIME to time_t
 * [in] s: ASN1_TIME structure
 * [returns] INVALID_TIME on error or time_t on success
 */
static time_t time_t_get_asn1_time(const ASN1_TIME *s)
{
    struct tm tm;

    if ((s == NULL) || (!ASN1_TIME_check(s))) {
        return INVALID_TIME;
    }
    if (ASN1_TIME_to_tm(s, &tm)) {
#ifdef _WIN32
        return _mkgmtime(&tm);
#else /* _WIN32 */
        return timegm(&tm);
#endif /* _WIN32 */
    } else {
        return INVALID_TIME;
    }
}

/*
 * Get signing time from authenticated attributes
 * [in] si: PKCS7_SIGNER_INFO structure
 * [returns] INVALID_TIME on error or time_t on success
 */
static time_t time_t_get_si_time(PKCS7_SIGNER_INFO *si)
{
    ASN1_UTCTIME *time = asn1_time_get_si_time(si);

    if (time == NULL)
        return INVALID_TIME; /* FAILED */
    return time_t_get_asn1_time(time);
}

/*
 * Get signing time from authenticated attributes cont[0]
 * [in] si: PKCS7_SIGNER_INFO structure
 * [returns] NULL on error or ASN1_UTCTIME on success
 */
static ASN1_UTCTIME *asn1_time_get_si_time(PKCS7_SIGNER_INFO *si)
{
    STACK_OF(X509_ATTRIBUTE) *auth_attr = PKCS7_get_signed_attributes(si);
    if (auth_attr) {
        int i;
        for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
            int nid = OBJ_txt2nid(PKCS9_SIGNING_TIME);
            X509_ATTRIBUTE *attr = X509at_get_attr(auth_attr, i);
            if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == nid) {
                /* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
                return X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
            }
        }
    }
    return NULL;
}

/*
 * Get sequence number from authenticated attributes cont[0]
 * [in] si: PKCS7_SIGNER_INFO structure
 * [returns] NULL on error or ASN1_UTCTIME on success
 */
static long get_sequence_number(PKCS7_SIGNER_INFO *si)
{
    STACK_OF(X509_ATTRIBUTE) *auth_attr = PKCS7_get_signed_attributes(si);
    if (auth_attr) {
        int i;
        for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
            int nid = OBJ_txt2nid(PKCS9_SEQUENCE_NUMBER);
            X509_ATTRIBUTE *attr = X509at_get_attr(auth_attr, i);
            if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == nid) {
                /* PKCS#9 sequence number - Policy OID:1.2.840.113549.1.9.25.4 */
                return ASN1_INTEGER_get(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_INTEGER, NULL));
            }
        }
    }
    return 0;
}

/*
 * Get timestamping time from embedded content in a CMS_ContentInfo structure
 * [in] si: CMS_ContentInfo structure
 * [returns] INVALID_TIME on error or time_t on success
 */
static time_t time_t_get_cms_time(CMS_ContentInfo *cms)
{
    time_t posix_time = INVALID_TIME;
    ASN1_OCTET_STRING **pos  = CMS_get0_content(cms);

    if (pos != NULL && *pos != NULL) {
        const u_char *p = (*pos)->data;
        TS_TST_INFO *token = d2i_TS_TST_INFO(NULL, &p, (*pos)->length);
        if (token) {
            const ASN1_GENERALIZEDTIME *asn1_time = TS_TST_INFO_get_time(token);
            posix_time = time_t_get_asn1_time(asn1_time);
            TS_TST_INFO_free(token);
        }
    }
    return posix_time;
}

/*
 * Create new CMS_ContentInfo struct for Authenticode Timestamp.
 * This struct does not contain any TS_TST_INFO as specified in RFC 3161.
 * [in] p7_signed: PKCS#7 signedData structure
 * [in] countersignature: Authenticode Timestamp decoded to PKCS7_SIGNER_INFO
 * [returns] pointer to CMS_ContentInfo structure
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

/*
 * The attribute type is SPC_INDIRECT_DATA_OBJID, so get a digest algorithm and a message digest
 * from the content and compare the message digest against the computed message digest of the file
 * [in] ctx: structure holds input and output data
 * [in] content: catalog file content
 * [returns] 1 on error or 0 on success
 */
static int verify_content_member_digest(FILE_FORMAT_CTX *ctx, ASN1_TYPE *content)
{
    int mdlen, mdtype = -1;
    u_char mdbuf[EVP_MAX_MD_SIZE];
    SpcIndirectDataContent *idc;
    const u_char *data;
    ASN1_STRING *value;
    const EVP_MD *md;
    u_char *cmdbuf = NULL;

    value = content->value.sequence;
    data = ASN1_STRING_get0_data(value);
    idc = d2i_SpcIndirectDataContent(NULL, &data, ASN1_STRING_length(value));
    if (!idc) {
        printf("Failed to extract SpcIndirectDataContent data\n");
        return 1; /* FAILED */
    }
    if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
        /* get a digest algorithm a message digest of the file from the content */
        mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
        memcpy(mdbuf, idc->messageDigest->digest->data, (size_t)idc->messageDigest->digest->length);
    }
    if (mdtype == -1) {
        printf("Failed to extract current message digest\n\n");
        SpcIndirectDataContent_free(idc);
        return 1; /* FAILED */
    }
    if (!ctx->format->digest_calc) {
        printf("Unsupported method: digest_calc\n");
        SpcIndirectDataContent_free(idc);
        return 1; /* FAILED */
    }
    md = EVP_get_digestbynid(mdtype);
    cmdbuf = ctx->format->digest_calc(ctx, md);
    if (!cmdbuf) {
        printf("Failed to compute a message digest value\n\n");
        SpcIndirectDataContent_free(idc);
        return 1; /* FAILED */
    }
    mdlen = EVP_MD_size(EVP_get_digestbynid(mdtype));
    if (memcmp(mdbuf, cmdbuf, (size_t)mdlen)) {
        OPENSSL_free(cmdbuf);
        SpcIndirectDataContent_free(idc);
        return 1; /* FAILED */
    } else {
        printf("Message digest algorithm  : %s\n", OBJ_nid2sn(mdtype));
        print_hash("Current message digest    ", "", mdbuf, mdlen);
        print_hash("Calculated message digest ", "\n", cmdbuf, mdlen);
    }
    OPENSSL_free(cmdbuf);

    if (idc->data && ctx->format->verify_indirect_data
        && !ctx->format->verify_indirect_data(ctx, idc->data)) {
        SpcIndirectDataContent_free(idc);
        return 1; /* FAILED */
    }
    SpcIndirectDataContent_free(idc);
    return 0; /* OK */
}

/*
 * Find the message digest of the file for all files added to the catalog file
 * CTL (MS_CTL_OBJID) is a list of hashes of certificates or a list of hashes files
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int verify_content(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    MsCtlContent *ctlc;
    int i;

    ctlc = ms_ctl_content_get(p7);
    if (!ctlc) {
        printf("Failed to extract MS_CTL_OBJID data\n");
        return 1; /* FAILED */
    }
    for (i = 0; i < sk_CatalogInfo_num(ctlc->header_attributes); i++) {
        int j;
        CatalogInfo *header_attr = sk_CatalogInfo_value(ctlc->header_attributes, i);
        if (header_attr == NULL)
            continue;
        for (j = 0; j < sk_CatalogAuthAttr_num(header_attr->attributes); j++) {
            char object_txt[128];
            CatalogAuthAttr *attribute;
            ASN1_TYPE *content;

            attribute = sk_CatalogAuthAttr_value(header_attr->attributes, j);
            if (!attribute)
                continue;
            content = catalog_content_get(attribute);
            if (!content)
                continue;
            object_txt[0] = 0x00;
            OBJ_obj2txt(object_txt, sizeof object_txt, attribute->type, 1);
            if (!strcmp(object_txt, SPC_INDIRECT_DATA_OBJID)) {
                /* SPC_INDIRECT_DATA_OBJID OID: 1.3.6.1.4.1.311.2.1.4 */
                if (!verify_content_member_digest(ctx, content)) {
                    /* computed message digest of the file is found in the catalog file */
                    ASN1_TYPE_free(content);
                    MsCtlContent_free(ctlc);
                    return 0; /* OK */
                }
            }
            ASN1_TYPE_free(content);
        }
    }
    MsCtlContent_free(ctlc);
    ERR_print_errors_fp(stdout);
    return 1; /* FAILED */
}

/*
 * [in] ctx: structure holds input and output data
 * [in] p7: PKCS#7 signature
 * [returns] 1 on error or 0 on success
 */
static int verify_signature(FILE_FORMAT_CTX *ctx, PKCS7 *p7)
{
    int leafok, verok;
    STACK_OF(X509) *signers;
    X509 *signer;
    CMS_ContentInfo *timestamp = NULL;
    time_t time;

    signers = PKCS7_get0_signers(p7, NULL, 0);
    if (!signers || sk_X509_num(signers) != 1) {
        printf("PKCS7_get0_signers error\n");
        return 1; /* FAILED */
    }
    signer = sk_X509_value(signers, 0);
    sk_X509_free(signers);
    printf("Signer's certificate:\n");
    print_cert(signer, 0);

    time = time_t_timestamp_get_attributes(&timestamp, p7, ctx->options->verbose);
    if (ctx->options->leafhash != NULL) {
        leafok = verify_leaf_hash(signer, ctx->options->leafhash);
        printf("\nLeaf hash match: %s\n", leafok ? "ok" : "failed");
        if (!leafok) {
            printf("Signature verification: failed\n\n");
            return 1; /* FAILED */
        }
    }
    if (ctx->options->catalog)
        printf("\nFile is signed in catalog: %s\n", ctx->options->catalog);
    printf("\nCAfile: %s\n", ctx->options->cafile);
    if (ctx->options->crlfile)
        printf("CRLfile: %s\n", ctx->options->crlfile);
    if (ctx->options->tsa_cafile)
        printf("TSA's certificates file: %s\n", ctx->options->tsa_cafile);
    if (ctx->options->tsa_crlfile)
        printf("TSA's CRL file: %s\n", ctx->options->tsa_crlfile);
    if (timestamp) {
        if (ctx->options->ignore_timestamp) {
            printf("\nTimestamp Server Signature verification is disabled\n");
            time = INVALID_TIME;
        } else {
            int timeok = verify_timestamp(ctx, p7, timestamp, time);
            printf("\nTimestamp Server Signature verification: %s\n", timeok ? "ok" : "failed");
            if (!timeok) {
                time = INVALID_TIME;
            }
        }
        CMS_ContentInfo_free(timestamp);
        ERR_clear_error();
    } else
        printf("\nTimestamp is not available\n\n");
    verok = verify_authenticode(ctx, p7, time, signer);
    printf("Signature verification: %s\n\n", verok ? "ok" : "failed");
    if (!verok)
        return 1; /* FAILED */

    return 0; /* OK */
}

/*
 * [in] ctx: structure holds input and output data
 * [returns] 1 on error or 0 on success
 */
static int verify_signed_file(FILE_FORMAT_CTX *ctx, GLOBAL_OPTIONS *options)
{
    int i, ret = 1, verified = 0;
    PKCS7 *p7;
    STACK_OF(PKCS7) *signatures = NULL;
    int detached = options->catalog ? 1 : 0;

    if (detached) {
        GLOBAL_OPTIONS *cat_options;
        FILE_FORMAT_CTX *cat_ctx;

        if (!ctx->format->is_detaching_supported || !ctx->format->is_detaching_supported()) {
            printf("This format does not support detached PKCS#7 signature\n");
            return 1; /* FAILED */
        }
        printf("Checking the specified catalog file\n\n");
        cat_options = OPENSSL_memdup(options, sizeof(GLOBAL_OPTIONS));
        if (!cat_options) {
            printf("OPENSSL_memdup error.\n");
            return 1; /* Failed */
        }
        cat_options->infile = options->catalog;
        cat_options->cmd = CMD_EXTRACT;
        cat_ctx = file_format_cat.ctx_new(cat_options, NULL, NULL);
        if (!cat_ctx) {
            printf("CAT file initialization error\n");
            return 1; /* Failed */
        }
        if (!cat_ctx->format->pkcs7_extract) {
            printf("Unsupported command: extract-signature\n");
            return 1; /* FAILED */
        }
        p7 = cat_ctx->format->pkcs7_extract(cat_ctx);
        cat_ctx->format->ctx_cleanup(cat_ctx);
        OPENSSL_free(cat_options);
    } else {
        if (!ctx->format->pkcs7_extract) {
            printf("Unsupported command: extract-signature\n");
            return 1; /* FAILED */
        }
        p7 = ctx->format->pkcs7_extract(ctx);
    }
    if (!p7) {
        printf("Unable to extract existing signature\n");
        return 1; /* FAILED */
    }
    signatures = signature_list_create(p7);
    if (!signatures) {
        printf("Failed to create signature list\n\n");
        sk_PKCS7_pop_free(signatures, PKCS7_free);
        return 1; /* FAILED */
    }
    for (i = 0; i < sk_PKCS7_num(signatures); i++) {
        PKCS7 *sig;

        if (options->index >= 0 && options->index != i) {
            printf("Warning: signature verification at index %d was skipped\n", i);
            continue;
        }
        sig = sk_PKCS7_value(signatures, i);
        if (detached) {
            if (!verify_content(ctx, sig)) {
                ret &= verify_signature(ctx, sig);
            } else {
                printf("Catalog verification: failed\n\n");
            }
            verified++;
        } else if (ctx->format->verify_digests) {
            printf("\nSignature Index: %d %s\n\n", i, i==0 ? " (Primary Signature)" : "");
            if (ctx->format->verify_digests(ctx, sig)) {
                ret &= verify_signature(ctx, sig);
            }
            verified++;
        } else {
            printf("Unsupported method: verify_digests\n");
            return 1; /* FAILED */
        }
    }
    printf("Number of verified signatures: %d\n", verified);
    sk_PKCS7_pop_free(signatures, PKCS7_free);
    if (ret)
        ERR_print_errors_fp(stdout);
    return ret;
}

/*
 * Insert PKCS#7 signature and its nested signatures to the sorted signature list
 * [in] p7: PKCS#7 signature
 * [returns] sorted signature list
 */
static STACK_OF(PKCS7) *signature_list_create(PKCS7 *p7)
{
    STACK_OF(PKCS7) *signatures = NULL;
    PKCS7_SIGNER_INFO *si;
    STACK_OF(X509_ATTRIBUTE) *unauth_attr;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info = PKCS7_get_signer_info(p7);

    if (!signer_info) {
        printf("Failed to obtain PKCS#7 signer info list\n");
        return 0; /* FAILED */
    }
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si) {
        printf("Failed to obtain PKCS#7 signer info value\n");
        return 0; /* FAILED */
    }
    signatures = sk_PKCS7_new(PKCS7_compare);
    if (!signatures) {
        printf("Failed to create new signature list\n");
        return 0; /* FAILED */
    }
    /* Unauthenticated attributes */
    unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
    if (unauth_attr) {
        /* find Nested Signature - Policy OID: 1.3.6.1.4.1.311.2.4.1 */
        int i;
        for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
            int nid = OBJ_txt2nid(SPC_NESTED_SIGNATURE_OBJID);
            X509_ATTRIBUTE *attr = X509at_get_attr(unauth_attr, i);
            if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == nid) {
                int j;

                for (j=0; j<X509_ATTRIBUTE_count(attr); j++) {
                    ASN1_STRING *value;
                    const u_char *data;
                    PKCS7 *nested;

                    value = X509_ATTRIBUTE_get0_data(attr, j, V_ASN1_SEQUENCE, NULL);
                    if (value == NULL)
                        continue;
                    data = ASN1_STRING_get0_data(value);
                    nested = d2i_PKCS7(NULL, &data, ASN1_STRING_length(value));
                    if (nested && !sk_PKCS7_push(signatures, nested)) {
                        printf("Failed to add nested signature\n");
                        PKCS7_free(nested);
                        sk_PKCS7_pop_free(signatures, PKCS7_free);
                        return NULL; /* FAILED */
                    }
                }
            }
        }
    }
    /* sort signatures in ascending order by signing time */
    sk_PKCS7_sort(signatures);
    /* insert the prime signature at index 0 */
    sk_PKCS7_unshift(signatures, p7);
    return signatures; /* OK */
}

/*
 * PKCS#7 signature comparison function
 * [in] a_ptr, b_ptr: pointers to PKCS#7 signatures
 * [returns] signatures order
 */
static int PKCS7_compare(const PKCS7 *const *a, const PKCS7 *const *b)
{
    PKCS7 *p7_a = NULL, *p7_b = NULL;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
    PKCS7_SIGNER_INFO *si;
    const ASN1_TIME *time_a, *time_b;
    long index_a, index_b;
    int ret = 0;

    p7_a = PKCS7_dup(*a);
    if (!p7_a)
        goto out;
    signer_info = PKCS7_get_signer_info(p7_a);
    if (!signer_info)
        goto out;
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        goto out;
    time_a = asn1_time_get_si_time(si);
    index_a = get_sequence_number(si);

    p7_b = PKCS7_dup(*b);
    if (!p7_b)
        goto out;
    signer_info = PKCS7_get_signer_info(p7_b);
    if (!signer_info)
        goto out;
    si = sk_PKCS7_SIGNER_INFO_value(signer_info, 0);
    if (!si)
        goto out;
    time_b = asn1_time_get_si_time(si);
    index_b = get_sequence_number(si);

    if (index_a == index_b)
        ret = ASN1_TIME_compare(time_a, time_b);
    else
        ret = (index_a == 0 || index_a < index_b) ? 1 : -1;

out:
    PKCS7_free(p7_a);
    PKCS7_free(p7_b);
    return ret;
}

/*
 * Retrieve a decoded PKCS#7 structure corresponding to the signature
 * stored in the "sigin" file
 * CMD_ATTACH command specific
 * [in] ctx: structure holds input and output data
 * [returns] pointer to PKCS#7 structure
 */
static PKCS7 *pkcs7_get_sigfile(FILE_FORMAT_CTX *ctx)
{
    PKCS7 *p7 = NULL;
    uint32_t filesize;
    char *indata;

    filesize = get_file_size(ctx->options->sigfile);
    if (!filesize) {
        return NULL; /* FAILED */
    }
    indata = map_file(ctx->options->sigfile, filesize);
    if (!indata) {
        printf("Failed to open file: %s\n", ctx->options->sigfile);
        return NULL; /* FAILED */
    }
    p7 = pkcs7_read_data(indata, filesize);
    unmap_file(indata, filesize);
    return p7;
}

/*
 * [in] options: structure holds the input data
 * [returns] 1 on error or 0 on success
 */
static int check_attached_data(GLOBAL_OPTIONS *options)
{
    FILE_FORMAT_CTX *ctx;
    GLOBAL_OPTIONS *tmp_options = NULL;

    tmp_options = OPENSSL_memdup(options, sizeof(GLOBAL_OPTIONS));
    if (!tmp_options) {
        printf("OPENSSL_memdup error.\n");
        return 1; /* Failed */
    }
    tmp_options->infile = options->outfile;
    tmp_options->cmd = CMD_VERIFY;

    ctx = file_format_script.ctx_new(tmp_options, NULL, NULL);
    if (!ctx)
        ctx = file_format_msi.ctx_new(tmp_options, NULL, NULL);
    if (!ctx)
        ctx = file_format_pe.ctx_new(tmp_options, NULL, NULL);
    if (!ctx)
        ctx = file_format_cab.ctx_new(tmp_options, NULL, NULL);
    if (!ctx)
        ctx = file_format_appx.ctx_new(tmp_options, NULL, NULL);
    if (!ctx)
        ctx = file_format_cat.ctx_new(tmp_options, NULL, NULL);
    if (!ctx) {
        printf("Corrupt attached signature\n");
        OPENSSL_free(tmp_options);
        return 1; /* Failed */
    }
    if (verify_signed_file(ctx, tmp_options)) {
        printf("Signature mismatch\n");
        ctx->format->ctx_cleanup(ctx);
        OPENSSL_free(tmp_options);
        return 1; /* Failed */
    }
    ctx->format->ctx_cleanup(ctx);
    OPENSSL_free(tmp_options);
    return 0; /* OK */
}

/*
 * [in, out] options: structure holds the input data
 * [returns] none
 */
static void free_options(GLOBAL_OPTIONS *options)
{
    /* If memory has not been allocated nothing is done */
    OPENSSL_free(options->cafile);
    OPENSSL_free(options->crlfile);
    OPENSSL_free(options->https_cafile);
    OPENSSL_free(options->https_crlfile);
    OPENSSL_free(options->tsa_cafile);
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
 * [in] argv0, cmd
 * [returns] none
 */
static void usage(const char *argv0, const char *cmd)
{
    const char *cmds_all[] = {"all", NULL};
    const char *cmds_sign[] = {"all", "sign", NULL};
    const char *cmds_extract_data[] = {"all", "extract-data", NULL};
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
        printf("%12s[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer  ]\n", "");
        printf("%12s[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n", "");
        printf("%12s[ -TSA-certs <TSA-certfile> ] [ -TSA-key <TSA-keyfile> ]\n", "");
        printf("%12s[ -TSA-time <unix-time> ]\n", "");
        printf("%12s[ -HTTPS-CAfile <infile> ]\n", "");
        printf("%12s[ -HTTPS-CRLfile <infile> ]\n", "");
        printf("%12s[ -time <unix-time> ]\n", "");
        printf("%12s[ -addUnauthenticatedBlob ]\n", "");
        printf("%12s[ -nest ]\n", "");
        printf("%12s[ -verbose ]\n", "");
        printf("%12s[ -add-msi-dse ]\n", "");
        printf("%12s[ -pem ]\n", "");
        printf("%12s[ -in ] <infile> [-out ] <outfile>\n\n", "");
    }
    if (on_list(cmd, cmds_extract_data)) {
        printf("%1sextract-data [ -pem ]\n", "");
        printf("%12s[ -h {md5,sha1,sha2(56),sha384,sha512} ]\n", "");
        printf("%12s[ -ph ]\n", "");
        printf("%12s[ -add-msi-dse ]\n", "");
        printf("%12s[ -in ] <infile> [ -out ] <datafile>\n\n", "");
    }
    if (on_list(cmd, cmds_add)) {
        printf("%1sadd [-addUnauthenticatedBlob]\n", "");
        printf("%12s[ -t <timestampurl> [ -t ... ] [ -p <proxy> ] [ -noverifypeer  ]\n", "");
        printf("%12s[ -ts <timestampurl> [ -ts ... ] [ -p <proxy> ] [ -noverifypeer ] ]\n", "");
        printf("%12s[ -TSA-certs <TSA-certfile> ] [ -TSA-key <TSA-keyfile> ]\n", "");
        printf("%12s[ -TSA-time <unix-time> ]\n", "");
        printf("%12s[ -HTTPS-CAfile <infile> ]\n", "");
        printf("%12s[ -HTTPS-CRLfile <infile> ]\n", "");
        printf("%12s[ -h {md5,sha1,sha2(56),sha384,sha512} ]\n", "");
        printf("%12s[ -index <index> ]\n", "");
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
        printf("%12s[ -p <proxy> ]\n", "");
        printf("%12s[ -index <index> ]\n", "");
        printf("%12s[ -ignore-timestamp ]\n", "");
        printf("%12s[ -ignore-cdp ]\n", "");
        printf("%12s[ -time <unix-time> ]\n", "");
        printf("%12s[ -require-leaf-hash {md5,sha1,sha2(56),sha384,sha512}:XXXXXXXXXXXX... ]\n", "");
        printf("%12s[ -verbose ]\n\n", "");
    }
}

/*
 * [in] argv0, cmd
 * [returns] none
 */
static void help_for(const char *argv0, const char *cmd)
{
    const char *cmds_all[] = {"all", NULL};
    const char *cmds_add[] = {"add", NULL};
    const char *cmds_attach[] = {"attach-signature", NULL};
    const char *cmds_extract[] = {"extract-signature", NULL};
    const char *cmds_remove[] = {"remove-signature", NULL};
    const char *cmds_sign[] = {"sign", NULL};
    const char *cmds_extract_data[] = {"extract-data", NULL};
    const char *cmds_verify[] = {"verify", NULL};
    const char *cmds_ac[] = {"sign", NULL};
    const char *cmds_add_msi_dse[] = {"add", "attach-signature", "sign", "extract-data", NULL};
    const char *cmds_addUnauthenticatedBlob[] = {"sign", "add", NULL};
#ifdef PROVIDE_ASKPASS
    const char *cmds_askpass[] = {"sign", NULL};
#endif /* PROVIDE_ASKPASS */
    const char *cmds_CAfile[] = {"attach-signature", "verify", NULL};
    const char *cmds_catalog[] = {"verify", NULL};
    const char *cmds_certs[] = {"sign", NULL};
    const char *cmds_comm[] = {"sign", NULL};
    const char *cmds_CRLfile[] = {"attach-signature", "verify", NULL};
    const char *cmds_CRLfileHTTPS[] = {"add", "sign", NULL};
    const char *cmds_CRLfileTSA[] = {"attach-signature", "verify", NULL};
    const char *cmds_h[] = {"add", "attach-signature", "sign", "extract-data", NULL};
    const char *cmds_i[] = {"sign", NULL};
    const char *cmds_in[] = {"add", "attach-signature", "extract-signature",
        "remove-signature", "sign", "extract-data", "verify", NULL};
    const char *cmds_index[] = {"add", "verify", NULL};
    const char *cmds_jp[] = {"sign", NULL};
    const char *cmds_key[] = {"sign", NULL};
#if OPENSSL_VERSION_NUMBER>=0x30000000L
    const char *cmds_nolegacy[] = {"sign", NULL};
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
    const char *cmds_n[] = {"sign", NULL};
    const char *cmds_nest[] = {"attach-signature", "sign", NULL};
    const char *cmds_noverifypeer[] = {"add", "sign", NULL};
    const char *cmds_out[] = {"add", "attach-signature", "extract-signature",
        "remove-signature", "sign", "extract-data", NULL};
    const char *cmds_p[] = {"add", "sign", "verify", NULL};
    const char *cmds_pass[] = {"sign", NULL};
    const char *cmds_pem[] = {"sign", "extract-data", "extract-signature", NULL};
    const char *cmds_ph[] = {"sign", "extract-data", NULL};
    const char *cmds_pkcs11cert[] = {"sign", NULL};
    const char *cmds_pkcs11engine[] = {"sign", NULL};
    const char *cmds_pkcs11module[] = {"sign", NULL};
    const char *cmds_pkcs12[] = {"sign", NULL};
    const char *cmds_readpass[] = {"sign", NULL};
    const char *cmds_require_leaf_hash[] = {"attach-signature", "verify", NULL};
    const char *cmds_sigin[] = {"attach-signature", NULL};
    const char *cmds_time[] = {"attach-signature", "sign", "verify", NULL};
    const char *cmds_ignore_timestamp[] = {"verify", NULL};
    const char *cmds_ignore_cdp[] = {"verify", NULL};
    const char *cmds_t[] = {"add", "sign", NULL};
    const char *cmds_ts[] = {"add", "sign", NULL};
    const char *cmds_CAfileHTTPS[] = {"add", "sign", NULL};
    const char *cmds_CAfileTSA[] = {"attach-signature", "verify", NULL};
    const char *cmds_certsTSA[] = {"add", "sign", NULL};
    const char *cmds_keyTSA[] = {"add", "sign", NULL};
    const char *cmds_timeTSA[] = {"add", "sign", NULL};
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
    if (on_list(cmd, cmds_extract_data)) {
        printf("\nUse the \"extract-data\" command to extract a data content to be signed.\n\n");
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
    if (on_list(cmd, cmds_index))
        printf("%-24s= use the signature at a certain position\n", "-index");
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
    if (on_list(cmd, cmds_noverifypeer))
        printf("%-24s= do not verify the Time-Stamp Authority's SSL certificate\n", "-noverifypeer");
    if (on_list(cmd, cmds_out))
        printf("%-24s= output file\n", "-out");
    if (on_list(cmd, cmds_p))
        printf("%-24s= proxy to connect to the desired Time-Stamp Authority server or CRL distribution point\n", "-p");
    if (on_list(cmd, cmds_pass))
        printf("%-24s= the private key password\n", "-pass");
    if (on_list(cmd, cmds_pem))
        printf("%-24s= PKCS#7 output data format PEM to use (default: DER)\n", "-pem");
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
    if (on_list(cmd, cmds_ignore_cdp))
        printf("%-24s= disable CRL Distribution Points online verification\n", "-ignore-cdp");
    if (on_list(cmd, cmds_t)) {
        printf("%-24s= specifies that the digital signature will be timestamped\n", "-t");
        printf("%26sby the Time-Stamp Authority (TSA) indicated by the URL\n", "");
        printf("%26sthis option cannot be used with the -ts option\n", "");
    }
    if (on_list(cmd, cmds_ts)) {
        printf("%-24s= specifies the URL of the RFC 3161 Time-Stamp Authority server\n", "-ts");
        printf("%26sthis option cannot be used with the -t option\n", "");
    }
    if (on_list(cmd, cmds_time))
        printf("%-24s= the unix-time to set the signing and/or verifying time\n", "-time");
    if (on_list(cmd, cmds_CAfileHTTPS))
        printf("%-24s= the file containing one or more HTTPS certificates in PEM format\n", "-HTTPS-CAfile");
    if (on_list(cmd, cmds_CRLfileHTTPS))
        printf("%-24s= the file containing one or more HTTPS CRLs in PEM format\n", "-HTTPS-CRLfile");
    if (on_list(cmd, cmds_CAfileTSA))
        printf("%-24s= the file containing one or more Time-Stamp Authority certificates in PEM format\n", "-TSA-CAfile");
    if (on_list(cmd, cmds_CRLfileTSA))
        printf("%-24s= the file containing one or more Time-Stamp Authority CRLs in PEM format\n", "-TSA-CRLfile");
    if (on_list(cmd, cmds_certsTSA))
        printf("%-24s= built-in Time-Stamp Authority signing certificate\n", "-TSA-certs");
    if (on_list(cmd, cmds_keyTSA))
        printf("%-24s= built-in Time-Stamp Authority private key or PKCS#11 URI identifies a key in the token\n", "-TSA-key");
    if (on_list(cmd, cmds_timeTSA))
        printf("%-24s= the unix-time to set the built-in Time-Stamp Authority signing\n", "-TSA-time");
    if (on_list(cmd, cmds_verbose))
        printf("%-24s= include additional output in the log\n", "-verbose");
    usage(argv0, cmd);
}

#ifdef PROVIDE_ASKPASS
/*
 * [in] prompt: "Password: "
 * [returns] password
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
#else /* HAVE_TERMIOS_H */
    return getpass(prompt);
#endif /* HAVE_TERMIOS_H */
}
#endif /* PROVIDE_ASKPASS */

/*
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
#else /* WIN32 */
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
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
 * [returns] pointer to STACK_OF(X509_CRL) structure
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
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
 * [in, out] options: structure holds the input data
 * [returns] PVK file
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
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
 * [in] options: structure holds the input data
 * [returns] pointer to ENGINE
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
 * [returns] pointer to ENGINE
 */
static ENGINE *engine_pkcs11(void)
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
 * [in, out] options: structure holds the input data
 * [in] engine: ENGINE structure
 * [returns] 0 on error or 1 on success
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
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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

    ret = 1; /* OK */
out:
    /* reset password */
    if (options->pass) {
        memset(options->pass, 0, strlen(options->pass));
        OPENSSL_free(options->pass);
    }
    return ret;
}

/*
 * [in] none
 * [returns] default CAfile
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
#endif /* WIN32 */
    return NULL;
}

static void print_version(void)
{
    char *cafile = get_cafile();

#ifdef PACKAGE_STRING
    printf("%s, using:\n", PACKAGE_STRING);
#else /* PACKAGE_STRING */
    printf("%s, using:\n", "osslsigncode custom build");
#endif /* PACKAGE_STRING */
    printf("\t%s (Library: %s)\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
#if OPENSSL_VERSION_NUMBER<0x30000000L
#ifdef ENABLE_CURL
    printf("\t%s\n", curl_version());
#else /* ENABLE_CURL */
    printf("\t%s\n", "no libcurl available");
#endif /* ENABLE_CURL */
#endif /* OPENSSL_VERSION_NUMBER<0x30000000L */
    if (cafile) {
        printf("Default -CAfile location: %s\n", cafile);
        OPENSSL_free(cafile);
    } else {
        printf("No default -CAfile location detected\n");
    }
#ifdef PACKAGE_BUGREPORT
    printf("\nPlease send bug-reports to " PACKAGE_BUGREPORT "\n");
#endif /* PACKAGE_BUGREPORT */
    printf("\n");
}

/*
 * [in] argv
 * [returns] cmd_type_t: command
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
    else if (!strcmp(argv[1], "extract-data"))
        return CMD_EXTRACT_DATA;
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

static int file_exists(const char *filename)
{
    if (filename) {
        FILE *file = fopen(filename, "rb");
        if (file) {
            fclose(file);
            return 1; /* File exists */
        }
    }
    return 0; /* File does not exist */
}

/*
 * [in] argc, argv
 * [in, out] options: structure holds the input data
 * [returns] 0 on error or 1 on success
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
    options->index = -1;
    options->nested_number = -1;
#if OPENSSL_VERSION_NUMBER>=0x30000000L
/* Use legacy PKCS#12 container with RC2-40-CBC private key and certificate encryption algorithm */
    options->legacy = 1;
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */

    if (cmd == CMD_HELP) {
        return 0; /* FAILED */
    }
    if (cmd == CMD_SIGN || cmd == CMD_VERIFY || cmd == CMD_ATTACH) {
        options->cafile = get_cafile();
        options->https_cafile = get_cafile();
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
        } else if ((cmd == CMD_SIGN || cmd == CMD_EXTRACT || cmd == CMD_EXTRACT_DATA)
                && !strcmp(*argv, "-pem")) {
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
#endif /* PROVIDE_ASKPASS */
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
        } else if ((cmd == CMD_SIGN || cmd == CMD_EXTRACT_DATA) && !strcmp(*argv, "-ph")) {
            options->pagehash = 1;
        } else if ((cmd == CMD_SIGN) && !strcmp(*argv, "-n")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->desc = *(++argv);
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_ATTACH
                || cmd == CMD_EXTRACT_DATA) && !strcmp(*argv, "-h")) {
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
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_VERIFY) && !strcmp(*argv, "-p")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->proxy = *(++argv);
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-noverifypeer")) {
            options->noverifypeer = 1;
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-addUnauthenticatedBlob")) {
            options->addBlob = 1;
        } else if ((cmd == CMD_SIGN || cmd == CMD_ATTACH) && !strcmp(*argv, "-nest")) {
            options->nest = 1;
        } else if ((cmd == CMD_ADD || cmd == CMD_VERIFY) && !strcmp(*argv, "-index")) {
            char *tmp_str;
            if (--argc < 1 ) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->index = (int)strtol(*(++argv), &tmp_str, 10);
            if (tmp_str == *argv ||  *tmp_str != '\0' || errno == ERANGE) { /* not a number */
                usage(argv0, "all");
                return 0; /* FAILED */
            }
        } else if ((cmd == CMD_VERIFY) && !strcmp(*argv, "-ignore-timestamp")) {
            options->ignore_timestamp = 1;
        } else if ((cmd == CMD_VERIFY) && !strcmp(*argv, "-ignore-cdp")) {
            options->ignore_cdp = 1;
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD || cmd == CMD_VERIFY) && !strcmp(*argv, "-verbose")) {
            options->verbose = 1;
        } else if ((cmd == CMD_SIGN || cmd == CMD_EXTRACT_DATA || cmd == CMD_ADD || cmd == CMD_ATTACH)
                && !strcmp(*argv, "-add-msi-dse")) {
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
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-HTTPS-CAfile")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            OPENSSL_free(options->https_cafile);
            options->https_cafile = OPENSSL_strdup(*++argv);
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-HTTPS-CRLfile")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->https_crlfile = OPENSSL_strdup(*++argv);
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
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-TSA-certs")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->tsa_certfile = *(++argv);
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-TSA-key")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->tsa_keyfile = *(++argv);
        } else if ((cmd == CMD_SIGN || cmd == CMD_ADD) && !strcmp(*argv, "-TSA-time")) {
            if (--argc < 1) {
                usage(argv0, "all");
                return 0; /* FAILED */
            }
            options->tsa_time = (time_t)strtoull(*(++argv), NULL, 10);
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
        } else if ((cmd == CMD_EXTRACT_DATA) && !strcmp(*argv, "--help")) {
            help_for(argv0, "extract-data");
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
    if (cmd != CMD_VERIFY && file_exists(options->outfile)) {
        printf("Overwriting an existing file is not supported.\n");
        return 0; /* FAILED */
    }
    if (argc > 0 ||
        (options->nturl && options->ntsurl) ||
        (options->nturl && options->tsa_certfile && options->tsa_keyfile) ||
        (options->ntsurl && options->tsa_certfile && options->tsa_keyfile) ||
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
    FILE_FORMAT_CTX *ctx = NULL;
    GLOBAL_OPTIONS options;
    PKCS7 *p7 = NULL, *cursig = NULL;
    BIO *outdata = NULL;
    BIO *hash = NULL;
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
        /* PKCS9_COUNTER_SIGNATURE exists as OpenSSL OBJ_pkcs9_countersignature */
        || !OBJ_create(MS_JAVA_SOMETHING, NULL, NULL)
        || !OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL)
        || !OBJ_create(SPC_NESTED_SIGNATURE_OBJID, NULL, NULL)
        || !OBJ_create(SPC_UNAUTHENTICATED_DATA_BLOB_OBJID, NULL, NULL)
        || !OBJ_create(SPC_RFC3161_OBJID, NULL, NULL)
        || !OBJ_create(PKCS9_SEQUENCE_NUMBER, NULL, NULL))
        DO_EXIT_0("Failed to create objects\n");

    /* commands and options initialization */
    if (!main_configure(argc, argv, &options))
        goto err_cleanup;
    if (!read_password(&options)) {
        DO_EXIT_1("Failed to read password from file: %s\n", options.readpass);
    }

    /* read key and certificates */
    if (options.cmd == CMD_SIGN && !read_crypto_params(&options))
        DO_EXIT_0("Failed to read key or certificates\n");

    if (options.cmd != CMD_VERIFY) {
        /* Create message digest BIO */
        hash = BIO_new(BIO_f_md());
        if (!BIO_set_md(hash, options.md)) {
            DO_EXIT_0("Unable to set the message digest of BIO\n");
        }
        /* Create outdata file */
        outdata = BIO_new_file(options.outfile, "w+bx");
        if (!outdata && errno != EEXIST)
            outdata = BIO_new_file(options.outfile, "w+b");
        if (!outdata) {
            BIO_free_all(hash);
            DO_EXIT_1("Failed to create file: %s\n", options.outfile);
        }
    }
    ctx = file_format_script.ctx_new(&options, hash, outdata);
    if (!ctx)
        ctx = file_format_msi.ctx_new(&options, hash, outdata);
    if (!ctx)
        ctx = file_format_pe.ctx_new(&options, hash, outdata);
    if (!ctx)
        ctx = file_format_cab.ctx_new(&options, hash, outdata);
    if (!ctx)
        ctx = file_format_appx.ctx_new(&options, hash, outdata);
    if (!ctx)
        ctx = file_format_cat.ctx_new(&options, hash, outdata);
    if (!ctx) {
        if (outdata && options.outfile) {
            /* unlink outfile */
            remove_file(options.outfile);
        }
        BIO_free_all(hash);
        BIO_free_all(outdata);
        outdata = NULL;
        ret = 1; /* FAILED */
        DO_EXIT_0("Initialization error or unsupported input file type.\n");
    }
    if (options.cmd == CMD_VERIFY) {
        ret = verify_signed_file(ctx, &options);
        goto skip_signing;
    } else if (options.cmd == CMD_EXTRACT_DATA) {
        if (!ctx->format->pkcs7_contents_get) {
            DO_EXIT_0("Unsupported command: extract-data\n");
        }
        p7 = ctx->format->pkcs7_contents_get(ctx, hash, options.md);
        if (!p7) {
            DO_EXIT_0("Unable to extract pkcs7 contents\n");
        }
        ret = data_write_pkcs7(ctx, outdata, p7);
        PKCS7_free(p7);
        goto skip_signing;
    } else if (options.cmd == CMD_EXTRACT) {
        if (!ctx->format->pkcs7_extract) {
            DO_EXIT_0("Unsupported command: extract-signature\n");
        }
        p7 = ctx->format->pkcs7_extract(ctx);
        if (!p7) {
            DO_EXIT_0("Unable to extract existing signature\n");
        }
        ret = data_write_pkcs7(ctx, outdata, p7);
        PKCS7_free(p7);
        goto skip_signing;
    } else if (options.cmd == CMD_REMOVE) {
        if (!ctx->format->remove_pkcs7) {
            DO_EXIT_0("Unsupported command: remove-signature\n");
        }
        ret = ctx->format->remove_pkcs7(ctx, hash, outdata);
        if (ret) {
            DO_EXIT_0("Unable to remove existing signature\n");
        }
        if (ctx->format->update_data_size) {
            ctx->format->update_data_size(ctx, outdata, NULL);
        }
        goto skip_signing;
    } else if (options.cmd == CMD_ADD) {
        if (!ctx->format->pkcs7_extract) {
            DO_EXIT_0("Unsupported command: add\n");
        }
        /* Obtain a current signature from previously-signed file */
        p7 = ctx->format->pkcs7_extract(ctx);
        if (!p7) {
            DO_EXIT_0("Unable to extract existing signature\n");
        }
        if (ctx->format->process_data) {
            ctx->format->process_data(ctx, hash, outdata);
        }
    } else if (options.cmd == CMD_ATTACH) {
        if (options.nest) {
            if (!ctx->format->pkcs7_extract_to_nest) {
                printf("Warning: Unsupported nesting (multiple signature)\n");
            } else {
                /* Obtain a current signature from previously-signed file */
                cursig = ctx->format->pkcs7_extract_to_nest(ctx);
                if (!cursig) {
                    DO_EXIT_0("Unable to extract existing signature\n");
                }
                options.nested_number = nested_signatures_number_get(cursig);
                if (options.nested_number < 0) {
                    PKCS7_free(cursig);
                    DO_EXIT_0("Unable to get number of nested signatures\n");
                }
            }
        }
        /* Obtain an existing PKCS#7 signature from a "sigin" file */
        p7 = pkcs7_get_sigfile(ctx);
        if (!p7) {
            PKCS7_free(cursig);
            DO_EXIT_0("Unable to extract valid signature\n");
        }
        if (ctx->format->process_data) {
            ctx->format->process_data(ctx, hash, outdata);
        }
    } else if (options.cmd == CMD_SIGN) {
        if (options.nest) {
            if (!ctx->format->pkcs7_extract_to_nest) {
                printf("Warning: Unsupported nesting (multiple signature)\n");
            } else {
                /* Obtain a current signature from previously-signed file */
                cursig = ctx->format->pkcs7_extract_to_nest(ctx);
                if (!cursig) {
                    DO_EXIT_0("Unable to extract existing signature\n");
                }
                options.nested_number = nested_signatures_number_get(cursig);
                if (options.nested_number < 0) {
                    PKCS7_free(cursig);
                    DO_EXIT_0("Unable to get number of nested signatures\n");
                }
            }
        }
        if (ctx->format->process_data) {
            ctx->format->process_data(ctx, hash, outdata);
        }
        if (ctx->format->pkcs7_signature_new) {
            /* Create a new PKCS#7 signature */
            p7 = ctx->format->pkcs7_signature_new(ctx, hash);
            if (!p7) {
                DO_EXIT_0("Unable to prepare new signature\n");
            }
        }
    } else {
        DO_EXIT_0("Unsupported command\n");
    }
    if (options.index > 0) {
        /* CMD_ADD or CMD_VERIFY */
        ret = add_nested_timestamp_and_blob(p7, ctx, options.index);
    } else {
        ret = add_timestamp_and_blob(p7, ctx);
    }
    if (ret) {
        PKCS7_free(p7);
        DO_EXIT_0("Unable to set unauthenticated attributes\n");
    }
    if (cursig) {
        /* CMD_SIGN or CMD_ATTACH */
        if (!cursig_set_nested(cursig, p7))
            DO_EXIT_0("Unable to append the nested signature to the current signature\n");
        PKCS7_free(p7);
        p7 = cursig;
        cursig = NULL;
    }
    if (ctx->format->append_pkcs7) {
        ret = ctx->format->append_pkcs7(ctx, outdata, p7);
        if (ret) {
            PKCS7_free(p7);
            DO_EXIT_0("Append signature to outfile failed\n");
        }
    }
    if (ctx->format->update_data_size) {
        ctx->format->update_data_size(ctx, outdata, p7);
    }
    PKCS7_free(p7);

skip_signing:
    if (ctx->format->bio_free) {
        ctx->format->bio_free(hash, outdata);
        outdata = NULL;
    }
    if (!ret && options.cmd == CMD_ATTACH) {
        ret = check_attached_data(&options);
        if (!ret)
            printf("Signature successfully attached\n");
        /* else
         * the new PKCS#7 signature has been successfully appended to the outfile
         * but only its verification failed (incorrect verification parameters?)
         * so the output file is not deleted
         */
    }

err_cleanup:
    if (outdata) {
        BIO *head = hash;
        int outdata_in_hash = 0;

        while (head) {
            BIO *tail = BIO_pop(head);

            if (head == outdata)
                outdata_in_hash = 1;
            BIO_free(head);
            head = tail;
        }
        if (!outdata_in_hash)
            BIO_free_all(outdata);

        if (options.outfile) {
            /* unlink outfile */
            remove_file(options.outfile);
        }
    }
    if (ctx && ctx->format->ctx_cleanup) {
        ctx->format->ctx_cleanup(ctx);
    }
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
   indent-tabs-mode: nil
End:

  vim: set ts=4 expandtab:
*/
