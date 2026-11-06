#!/usr/bin/python3
"""Make PE files with crafted RFC 3161 timestamps for verification tests.

The signature uses the expired test certificate, valid only during 2018, so
it verifies only with a valid timestamp from 2018.  Timestamp tokens are
signed with the test TSA key; DER is built here so that only the
cryptography module is needed.
"""

import argparse
import datetime
import hashlib
import os
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA = "1.2.840.113549.1.1.1"
OID_RFC3161 = "1.3.6.1.4.1.311.3.3.1"
OID_POLICY = "1.3.6.1.4.1.42921.1.2.2"
SIGNING_TIME = datetime.datetime(2018, 6, 1, tzinfo=datetime.timezone.utc)
LATE_TIME = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
SKI_MARKER = b"\x5a" * 20


# Minimal DER encoding

def der_len(length):
    """DER length octets"""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag, body):
    """Tag, length and value"""
    return bytes([tag]) + der_len(len(body)) + body


def seq(*items):
    """SEQUENCE of encoded items"""
    return tlv(0x30, b"".join(items))


def set_of(*items):
    """SET OF encoded items in DER order"""
    return tlv(0x31, b"".join(sorted(items)))


def integer(value):
    """INTEGER"""
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True))


def oid(dotted):
    """OBJECT IDENTIFIER from dotted notation"""
    arcs = [int(arc) for arc in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7f]
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7f))
            arc >>= 7
        body += bytes(chunk)
    return tlv(0x06, body)


def octets(data):
    """OCTET STRING"""
    return tlv(0x04, data)


def algorithm(dotted):
    """AlgorithmIdentifier with NULL parameters"""
    return seq(oid(dotted), b"\x05\x00")


def generalized_time(when):
    """GeneralizedTime in UTC"""
    return tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode())


# Minimal DER parsing

def parse(data, pos=0):
    """Return (tag, start, content_start, end) of the element at pos."""
    tag = data[pos]
    length = data[pos + 1]
    content = pos + 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[content:content + count], "big")
        content += count
    return tag, pos, content, content + length


def children(data, element):
    """Child elements of a constructed element"""
    _, _, pos, end = element
    result = []
    while pos < end:
        child = parse(data, pos)
        result.append(child)
        pos = child[3]
    return result


def raw(data, element):
    """Complete encoding of an element"""
    return data[element[1]:element[3]]


def signer_info_path(sig):
    """Return the ContentInfo, SignedData and first SignerInfo elements."""
    content_info = parse(sig)
    signed_data = parse(sig, children(sig, children(sig, content_info)[1])[0][1])
    signer_infos = children(sig, signed_data)[-1]
    return content_info, signed_data, signer_infos, children(sig, signer_infos)[0]


def encrypted_digest(sig):
    """encryptedDigest of the first SignerInfo"""
    signer_info = signer_info_path(sig)[3]
    value = next(c for c in children(sig, signer_info) if c[0] == 0x04)
    return sig[value[2]:value[3]]


def with_unsigned_attributes(sig, attributes):
    """Replace the unsigned attributes of the first SignerInfo."""
    content_info, signed_data, signer_infos, signer_info = signer_info_path(sig)
    fields = [raw(sig, c) for c in children(sig, signer_info) if c[0] != 0xa1]
    new_signer_info = seq(*fields, tlv(0xa1, b"".join(sorted(attributes))))
    others = [raw(sig, c) for c in children(sig, signer_infos)[1:]]
    new_signer_infos = tlv(0x31, new_signer_info + b"".join(others))
    sd_fields = [raw(sig, c) for c in children(sig, signed_data)[:-1]]
    new_signed_data = seq(*sd_fields, new_signer_infos)
    return seq(raw(sig, children(sig, content_info)[0]), tlv(0xa0, new_signed_data))


# Timestamp tokens

def tst_info(imprint, when, serial):
    """TSTInfo with a SHA-256 message imprint"""
    return seq(integer(1), oid(OID_POLICY),
               seq(algorithm(OID_SHA256), octets(imprint)),
               integer(serial), generalized_time(when))


def token(tst, certs, signer_info):
    """Timestamp token: SignedData with TSTInfo content"""
    signed_data = seq(
        integer(3),
        set_of(algorithm(OID_SHA256)),
        seq(oid(OID_TST_INFO), tlv(0xa0, octets(tst))),
        tlv(0xa0, b"".join(sorted(c.public_bytes(serialization.Encoding.DER) for c in certs))),
        set_of(signer_info))
    return seq(oid(OID_SIGNED_DATA), tlv(0xa0, signed_data))


def signed_token(tst, tsa_cert, tsa_key, chain):
    """Token signed by the TSA; also returns its signature"""
    attrs = [seq(oid(OID_CONTENT_TYPE), set_of(oid(OID_TST_INFO))),
             seq(oid(OID_MESSAGE_DIGEST), set_of(octets(hashlib.sha256(tst).digest())))]
    attrs_body = b"".join(sorted(attrs))
    signature = tsa_key.sign(tlv(0x31, attrs_body), padding.PKCS1v15(), hashes.SHA256())
    signer_info = seq(
        integer(1),
        seq(tsa_cert.issuer.public_bytes(), integer(tsa_cert.serial_number)),
        algorithm(OID_SHA256),
        tlv(0xa0, attrs_body),
        algorithm(OID_RSA),
        octets(signature))
    return token(tst, chain, signer_info), signature


def unsigned_token(tst, padding_certs):
    """Unverifiable token: subjectKeyIdentifier signer, dummy signature."""
    signer_info = seq(integer(3), tlv(0x80, SKI_MARKER), algorithm(OID_SHA256),
                      algorithm(OID_RSA), octets(b"\0" * 256))
    return token(tst, padding_certs, signer_info)


def rfc3161_attribute(*tokens):
    """Unsigned attribute with RFC 3161 timestamp tokens"""
    return seq(oid(OID_RFC3161), set_of(*tokens))


def load_certs(path):
    """Certificates from a PEM file"""
    with open(path, "rb") as file:
        data = file.read()
    marker = b"-----END CERTIFICATE-----"
    blocks = [block + marker for block in data.split(marker) if b"-----BEGIN" in block]
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def run(*args):
    """Run a command and exit if it fails"""
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, check=False)
    if proc.returncode:
        print(proc.stdout)
        sys.exit("Failed: " + " ".join(args))


def main():  # pylint: disable=too-many-locals
    """Make the crafted timestamp test files"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--osslsigncode", required=True)
    parser.add_argument("--certs", required=True)
    parser.add_argument("--in", dest="infile", required=True)
    parser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args()

    tsa_cert = load_certs(os.path.join(args.certs, "TSA.pem"))[0]
    chain = load_certs(os.path.join(args.certs, "tsa-chain.pem"))
    with open(os.path.join(args.certs, "TSA.key"), "rb") as file:
        tsa_key = serialization.load_pem_private_key(file.read(), password=None)

    def out(name):
        path = os.path.join(args.out, name)
        if os.path.exists(path):
            os.remove(path)
        return path

    signed = out("ts_crafted_signed.exe")
    sig_file = out("ts_crafted_signed.der")
    run(args.osslsigncode, "sign",
        "-certs", os.path.join(args.certs, "expired.pem"),
        "-key", os.path.join(args.certs, "key.pem"),
        "-ac", os.path.join(args.certs, "CAcross.pem"),
        "-h", "sha256", "-time", str(int(SIGNING_TIME.timestamp())),
        "-in", args.infile, "-out", signed)
    run(args.osslsigncode, "extract-signature", "-in", signed, "-out", sig_file)
    with open(sig_file, "rb") as file:
        sig = file.read()
    imprint = hashlib.sha256(encrypted_digest(sig)).digest()

    good, _ = signed_token(tst_info(imprint, SIGNING_TIME, 1), tsa_cert, tsa_key, chain)
    late, late_signature = signed_token(tst_info(imprint, LATE_TIME, 2), tsa_cert, tsa_key, chain)
    empty, _ = signed_token(tst_info(b"", SIGNING_TIME, 3), tsa_cert, tsa_key, chain)
    short, _ = signed_token(tst_info(imprint[:1], SIGNING_TIME, 4), tsa_cert, tsa_key, chain)
    # Padded so that DER stores it after the late token
    unverifiable = unsigned_token(tst_info(imprint, SIGNING_TIME, 5), chain * 8)

    cases = {
        "ts_crafted_ok.exe": [rfc3161_attribute(good)],
        "ts_crafted_late.exe": [rfc3161_attribute(late)],
        "ts_crafted_empty.exe": [rfc3161_attribute(empty)],
        "ts_crafted_short.exe": [rfc3161_attribute(short)],
        "ts_crafted_two_attrs.exe": [rfc3161_attribute(late), rfc3161_attribute(unverifiable)],
    }
    for name, attributes in cases.items():
        der = out(name + ".der")
        with open(der, "wb") as file:
            file.write(with_unsigned_attributes(sig, attributes))
        run(args.osslsigncode, "attach-signature", "-sigin", der,
            "-in", args.infile, "-out", out(name))
        os.remove(der)

    # The two-attribute case needs the unverifiable attribute stored second
    with open(os.path.join(args.out, "ts_crafted_two_attrs.exe"), "rb") as file:
        attached = file.read()
    if not 0 <= attached.find(late_signature) < attached.find(SKI_MARKER):
        sys.exit("ts_crafted_two_attrs.exe: unexpected timestamp order")
    os.remove(signed)
    os.remove(sig_file)


if __name__ == "__main__":
    main()
