#!/usr/bin/env python3
"""CAB SIP regressions, with independent digest and RSA checks."""
import argparse
import hashlib
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from check_signtool_compat import (make_certificate, parse_der, pkcs7_layout, run,
                                  SIGNING_TIME, MESSAGE_DIGEST)


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length() + 7) // 8, "big")
    if size >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + body


def replace_content(blob, content, key, digest):
    """Make a legacy test signature with the disposable key, not a patched file signature."""
    outer = parse_der(blob)[0].children()
    signed = outer[1].children()[0].children()
    old_content = signed[2].children()
    new_content = tlv(0x30, old_content[0].encoded + tlv(0xa0, content))
    signer = signed[-1].children()[0].children()
    attrs = []
    for attr in signer[3].children():
        oid, values = attr.children()
        if oid.body == MESSAGE_DIGEST:
            values = parse_der(tlv(0x31, tlv(4, hashlib.new(digest, parse_der(content)[0].body).digest())))[0]
        attrs.append(tlv(0x30, oid.encoded + values.encoded))
    attrs = b"".join(sorted(attrs))
    sig = key.sign(tlv(0x31, attrs), padding.PKCS1v15(), getattr(hashes, digest.upper())())
    signer = (b"".join(n.encoded for n in signer[:3]) + tlv(0xa0, attrs)
              + signer[4].encoded + tlv(4, sig))
    signed = (b"".join(n.encoded for n in signed[:2]) + new_content
              + b"".join(n.encoded for n in signed[3:-1]) + tlv(0x31, tlv(0x30, signer)))
    return tlv(0x30, outer[0].encoded + tlv(0xa0, tlv(0x30, signed)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osslsigncode")
    parser.add_argument("files", type=Path)
    args = parser.parse_args()
    originals = {p: p.read_bytes() for p in args.files.glob("unsigned.*")}
    tool = args.osslsigncode
    with tempfile.TemporaryDirectory(prefix="sip-formats-") as tmp:
        directory = Path(tmp)
        key, cert, key_file = make_certificate(directory)
        counter = 0

        def verify(path):
            run([tool, "verify", "-CAfile", cert, "-in", path])

        def extract(path):
            nonlocal counter
            counter += 1
            der = directory / (str(counter) + ".der")
            run([tool, "extract-signature", "-in", path, "-out", der])
            return der.read_bytes(), der

        def sign(source, digest="sha256", extra=(), error=None):
            nonlocal counter
            counter += 1
            output = directory / (str(counter) + source.suffix)
            run([tool, "sign", "-certs", cert, "-key", key_file, "-h", digest,
                 *extra, "-in", source, "-out", output], error)
            if error is None:
                verify(output)
            return output

        def detached(source, digest, flags=()):
            nonlocal counter
            counter += 1
            data = directory / (str(counter) + ".data")
            run([tool, "extract-data", "-h", digest, *flags, "-in", source, "-out", data])
            signature = sign(data, digest)
            output = directory / (str(counter) + "-detached" + source.suffix)
            run([tool, "attach-signature", "-h", digest, *flags, "-sigin", signature,
                 "-in", source, "-out", output])
            verify(output)
            return output

        def content(path, digest):
            blob, _ = extract(path)
            attrs, value = pkcs7_layout(blob, key.public_key(), digest)
            assert SIGNING_TIME not in attrs
            return blob, value.children()

        # CAB v2: the auxiliary hash covers four little-endian cbCabinet bytes.
        for digest in ("sha1", "sha256", "sha512"):
            source = args.files / "unsigned.ex_"
            output = sign(source, digest)
            blob, value = content(output, digest)
            subject, main_digest = value
            assert subject.children()[0].body.hex() == "2b06010401823702011c"
            link = subject.children()[1]
            assert link.tag == 0xa1
            clsid, serialized = link.children()
            assert clsid.body.hex() == "a6b586d5b4a12466ae05a217da8e60d6"
            attribute = parse_der(serialized.body)[0].children()[0].children()
            assert attribute[0].body.hex() == "2b060104018237020501"
            data = output.read_bytes()
            assert attribute[1].children()[0].body == hashlib.new(digest, data[8:12]).digest()
            sigpos = struct.unpack_from("<I", data, 44)[0]
            assert main_digest.children()[1].body == hashlib.new(
                digest, data[:4] + data[8:34] + data[56:sigpos]).digest()
            assert sign(output, digest).read_bytes() == data
            nested = sign(output, digest, ("-nest",))
            verify(nested)
            _, der = extract(output)
            attached = directory / ("attached-" + digest + ".cab")
            run([tool, "attach-signature", "-h", digest, "-sigin", der,
                 "-in", source, "-out", attached])
            verify(attached)
            assert attached.read_bytes() == data
            assert detached(source, digest).read_bytes() == data
            if digest == "sha256":
                legacy_subject = tlv(0x30, tlv(6, bytes.fromhex('2b060104018237020119'))
                    + tlv(0xa2, tlv(0x80, '<<<Obsolete>>>'.encode('utf-16-be'))))
                legacy_blob = replace_content(blob, tlv(0x30, legacy_subject + main_digest.encoded), key, digest)
                legacy_blob += bytes((-len(legacy_blob)) % 8)
                header = bytearray(data[:sigpos])
                struct.pack_into('<I', header, 48, len(legacy_blob))
                legacy = directory / 'legacy.cab'
                legacy.write_bytes(header + legacy_blob)
                verify(legacy)
                sign(legacy, digest, ('-nest',))

    assert all(path.read_bytes() == data for path, data in originals.items())
    print('CAB v2 subject and digests verified')


if __name__ == '__main__':
    main()
