#!/usr/bin/env python3
"""Check PE page hashes independently, without Windows or a timestamp service."""

import argparse
import hashlib
import struct
import tempfile
from pathlib import Path

from check_pe_checksum import pe_checksum
from check_signtool_compat import (make_certificate, parse_der, pkcs7_layout, run,
                                  signature_layout)
from check_sip_formats import replace_content, tlv
from make_large_pe import make_pe


CLASS_ID = bytes.fromhex("a6b586d5b4a12466ae05a217da8e60d6")
PAGE_HASH_V1 = bytes.fromhex("2b060104018237020301")
PAGE_HASH_V2 = bytes.fromhex("2b060104018237020302")


def pe_layout(data):
    """Return the optional header, section table, count, and certificate directory."""
    pe = struct.unpack_from("<I", data, 60)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic in (0x10b, 0x20b)
    directory = opt + (96 if magic == 0x10b else 112) + 32
    return opt, opt + opt_size, count, directory


def page_hashes(data, digest):
    """Compute all offset/digest records, including headers and the terminator."""
    opt, sections, count, directory = pe_layout(data)
    page_size = struct.unpack_from("<I", data, opt + 32)[0]
    header_size = struct.unpack_from("<I", data, opt + 60)[0]
    checksum = opt + 64
    header = (data[:checksum] + data[checksum + 4:directory]
              + data[directory + 8:header_size] + bytes(page_size - header_size))
    result = bytearray(struct.pack("<I", 0) + hashlib.new(digest, header).digest())
    end = 0
    for index in range(count):
        size, offset = struct.unpack_from("<II", data, sections + index * 40 + 16)
        if not size:
            continue
        for start in range(offset, offset + size, page_size):
            page = data[start:min(start + page_size, offset + size)]
            page = page.ljust(page_size, b"\0")
            result += struct.pack("<I", start) + hashlib.new(digest, page).digest()
        end = offset + size
    result += struct.pack("<I", end) + bytes(hashlib.new(digest).digest_size)
    return bytes(result)


def page_hash_content(content, payload, oid):
    """Replace only the page-hash subject data, retaining the file digest."""
    subject, file_digest = content.children()
    subject_oid, image = subject.children()
    flags = image.children()[0]
    attribute = tlv(0x30, tlv(6, oid) + tlv(0x31, tlv(4, payload)))
    moniker = tlv(0xa1, tlv(4, CLASS_ID) + tlv(4, tlv(0x31, attribute)))
    image = tlv(0x30, flags.encoded + tlv(0xa0, moniker))
    subject = tlv(0x30, subject_oid.encoded + image)
    return tlv(0x30, subject + file_digest.encoded)


def embed_signature(original, blob):
    """Embed a test signature directly, so attach-signature cannot reject it first."""
    opt, _, _, directory = pe_layout(original)
    offset = struct.unpack_from("<I", original, directory)[0]
    data = bytearray(original[:offset])
    size = (8 + len(blob) + 7) & ~7
    data += struct.pack("<IHH", size, 0x200, 2) + blob + bytes(size - 8 - len(blob))
    struct.pack_into("<II", data, directory, offset, size)
    struct.pack_into("<I", data, opt + 64, pe_checksum(data))
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osslsigncode")
    parser.add_argument("files", type=Path)
    args = parser.parse_args()
    original = (args.files / "unsigned.exe").read_bytes()
    with tempfile.TemporaryDirectory(prefix="pe-page-hashes-") as tmp:
        directory = Path(tmp)
        key, cert, key_file = make_certificate(directory)
        tool = args.osslsigncode
        counter = 0

        def output(suffix):
            nonlocal counter
            counter += 1
            return directory / (str(counter) + suffix)

        def verify(path, error=None):
            return run([tool, "verify", "-CAfile", cert, "-in", path], error)

        def sign(source, digest, extra=()):
            path = output(source.suffix)
            run([tool, "sign", "-certs", cert, "-key", key_file, "-h", digest,
                 *extra, "-in", source, "-out", path])
            verify(path)
            return path

        def extract(path):
            der = output(".der")
            run([tool, "extract-signature", "-in", path, "-out", der])
            return der.read_bytes()

        # PE32+ with a partial last page, a zero-sized .bss, and an overlay.
        # Its 17 records also make SHA-256's table length divisible by the
        # SHA-512 record size: length divisibility alone cannot identify a hash.
        pe64 = directory / "pe64.exe"
        make_pe(str(pe64), 512 + 14 * 4096 + 512)
        data = bytearray(pe64.read_bytes())
        opt, sections, _, _ = pe_layout(data)
        struct.pack_into("<H", data, opt - 18, 2)
        struct.pack_into("<I", data, opt + 56, 0x11000)
        data[sections + 40:sections + 80] = struct.pack(
            "<8sIIIIIIHHI", b".bss", 4096, 0x10000, 0, 0, 0, 0, 0, 0, 0xc0000080)
        pe64.write_bytes(data + b"unsigned overlay")

        for source in (args.files / "unsigned.exe", pe64):
            for digest in ("sha1", "sha256", "sha384", "sha512"):
                signed = sign(source, digest, ("-ph",))
                data = signed.read_bytes()
                _, flags, link = signature_layout(signed, key.public_key(), digest)
                assert flags.encoded == bytes.fromhex("030100") and link.tag == 0xa1
                clsid, serialized = link.children()
                assert clsid.body == CLASS_ID
                oid, values = parse_der(serialized.body)[0].children()[0].children()
                expected_oid = PAGE_HASH_V1 if digest == "sha1" else PAGE_HASH_V2
                assert oid.body == expected_oid
                expected = page_hashes(data, digest)
                assert values.children()[0].body == expected
                assert "Page hash algorithm  : " + digest.upper() in verify(signed).stdout
                assert sign(signed, digest, ("-ph",)).read_bytes() == data
                sign(signed, digest, ("-ph", "-nest"))

                # Extract-data must choose the same page-hash algorithm as sign.
                unsigned_data = output(".data")
                run([tool, "extract-data", "-ph", "-h", digest,
                     "-in", source, "-out", unsigned_data])
                detached = sign(unsigned_data, digest)
                attached = output(".exe")
                run([tool, "attach-signature", "-sigin", detached,
                     "-in", source, "-out", attached])
                verify(attached)
                assert attached.read_bytes() == data

                blob = extract(signed)
                _, content = pkcs7_layout(blob, key.public_key(), digest)

                def with_page_hashes(payload, page_oid=expected_oid):
                    replacement = page_hash_content(content, payload, page_oid)
                    signature = replace_content(blob, replacement, key, digest)
                    # Confirm that negative tests have valid RSA signatures and
                    # content digests: only the page-hash table should fail.
                    pkcs7_layout(signature, key.public_key(), digest)
                    path = output(".exe")
                    path.write_bytes(embed_signature(data, signature))
                    return path

                if digest in ("sha384", "sha512"):
                    legacy = with_page_hashes(page_hashes(data, "sha256"))
                    assert "Page hash algorithm  : SHA256" in verify(legacy).stdout
                    assert sign(legacy, digest, ("-ph",)).read_bytes() == data
                    sign(legacy, digest, ("-ph", "-nest"))

                # Reject incorrect offsets, digests, terminators, partial records,
                # missing records, and V1/V2 OID mismatches, even when re-signed.
                stride = 4 + hashlib.new(digest).digest_size
                bad_offset = bytes([expected[0] ^ 1]) + expected[1:]
                bad_digest = expected[:4] + bytes([expected[4] ^ 1]) + expected[5:]
                bad_end = expected[:-1] + b"\x01"
                for payload in (bad_offset, bad_digest, bad_end, expected[:-1], expected[:-stride]):
                    result = verify(with_page_hashes(payload), "Signature verification: failed")
                    assert "Page hash" in result.stdout, result.stdout
                other_oid = PAGE_HASH_V2 if digest == "sha1" else PAGE_HASH_V1
                verify(with_page_hashes(expected, other_oid), "Signature verification: failed")

    assert (args.files / "unsigned.exe").read_bytes() == original
    print("SHA-1/256/384/512 PE page hashes checked independently; legacy SHA-256, "
          "re-signing, nesting, detached signing and malformed tables verified")


if __name__ == "__main__":
    main()
