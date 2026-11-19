#!/usr/bin/env python3
"""Exercise default Authenticode metadata using disposable, currently valid keys.

No timestamp service or installed signing certificate is used. Check DER,
content digests, RSA signatures and PE checksums independently of osslsigncode.
"""

import argparse
import datetime
import hashlib
import struct
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from check_pe_checksum import pe_checksum


CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")
MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
SIGNING_TIME = bytes.fromhex("2a864886f70d010905")
OPUS_INFO = bytes.fromhex("2b06010401823702010c")


@dataclass(frozen=True)
class DER:
    """One definite-length ASN.1 TLV in a test-generated signature."""

    tag: int
    body: bytes
    encoded: bytes

    def children(self):
        return parse_der(self.body)


def parse_der(data):
    """Parse a sequence of definite-length, single-byte-tag TLVs."""
    nodes = []
    pos = 0
    while pos < len(data):
        start = pos
        tag, size = data[pos:pos + 2]
        pos += 2
        if size & 0x80:
            count = size & 0x7f
            assert 0 < count <= 4
            size = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        end = pos + size
        assert end <= len(data)
        nodes.append(DER(tag, data[pos:end], data[start:end]))
        pos = end
    return nodes


def signature_layout(path, public_key, digest="sha1"):
    """Validate one PE signature, returning its attributes and PE image data."""
    data = Path(path).read_bytes()
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    opt = pe_offset + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic in (0x10b, 0x20b)
    directory = opt + (96 if magic == 0x10b else 112) + 8 * 4
    offset, size = struct.unpack_from("<II", data, directory)
    assert offset % 8 == 0 and size % 8 == 0 and offset + size == len(data)
    length, revision, cert_type = struct.unpack_from("<IHH", data, offset)
    assert length == size and revision == 0x200 and cert_type == 2
    assert struct.unpack_from("<I", data, opt + 64)[0] == pe_checksum(data)

    # Strip only the WIN_CERTIFICATE alignment padding, not bytes inside DER.
    blob = data[offset + 8:offset + size]
    header = 2 + ((blob[1] & 0x7f) if blob[1] & 0x80 else 0)
    content_len = (int.from_bytes(blob[2:header], "big")
                   if header > 2 else blob[1])
    assert not any(blob[header + content_len:])
    attrs, content = pkcs7_layout(blob[:header + content_len], public_key, digest)
    image = content.children()[0].children()[1].children()
    assert image[0].tag == 3 and image[1].tag == 0xa0
    link = image[1].children()[0]
    return attrs, image[0], link


def pkcs7_layout(blob, public_key, digest):
    """Validate signed attributes and content digest for any Authenticode SIP."""
    pkcs7 = parse_der(blob)[0]
    signed = pkcs7.children()[1].children()[0].children()
    content = signed[2].children()[1].children()[0]
    assert content.tag == 0x30
    signers = signed[-1].children()
    assert len(signers) == 1
    signer = signers[0].children()
    assert len(signer) == 6  # No unsigned timestamp attributes.
    assert signer[3].tag == 0xa0
    attrs = {}
    for attr in signer[3].children():
        oid, values = attr.children()
        assert oid.body not in attrs
        attrs[oid.body] = values
    assert CONTENT_TYPE in attrs and MESSAGE_DIGEST in attrs
    assert attrs[MESSAGE_DIGEST].children()[0].body == hashlib.new(
        digest, content.body).digest()
    # Authenticode signs a SET encoding, not the context-specific [0] tag.
    public_key.verify(signer[-1].body, b"\x31" + signer[3].encoded[1:],
                      padding.PKCS1v15(), getattr(hashes, digest.upper())())
    return attrs, content


def make_certificate(directory, publisher=None):
    """Create an isolated self-signed code-signing certificate and private key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                        "osslsigncode compatibility test")])
    if publisher is not None:
        name = x509.Name.from_rfc4514_string(publisher.replace(", ", ","),
            {"E": NameOID.EMAIL_ADDRESS, "S": NameOID.STATE_OR_PROVINCE_NAME})
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return key, cert_path, key_path


def run(args, expected_error=None):
    """Run osslsigncode and retain diagnostics on failure."""
    result = subprocess.run([str(arg) for arg in args], check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    if expected_error is not None:
        assert result.returncode != 0 and expected_error in result.stdout, result.stdout
    else:
        assert result.returncode == 0, result.stdout
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osslsigncode")
    parser.add_argument("files", type=Path)
    args = parser.parse_args()
    originals = {path: path.read_bytes() for path in args.files.glob("unsigned.*")}
    # AppX signing certificates must match the package publisher. Use the same
    # disposable certificate for all formats to keep this test self-contained.
    with zipfile.ZipFile(args.files / "unsigned.256appx") as archive:
        manifest = ET.fromstring(archive.read("AppxManifest.xml"))
    publisher = next(child for child in manifest if child.tag.endswith("Identity")).attrib["Publisher"]
    with tempfile.TemporaryDirectory(prefix="signtool-compat-") as tmp:
        directory = Path(tmp)
        key, cert, key_file = make_certificate(directory, publisher)
        command = [args.osslsigncode, "sign", "-certs", cert, "-key", key_file]

        def sign(case, extra, digest="sha1", ext="exe"):
            output = directory / (case + "." + ext)
            result = run(command + ["-h", digest] + extra + ["-in", args.files / ("unsigned." + ext),
                                                            "-out", output])
            for option in ("-st", "-time"):
                if option in extra:
                    assert option + " is deprecated and ignored when signing" in result.stdout
            if ext == "exe":
                layout = signature_layout(output, key.public_key(), digest)
            else:
                der = directory / (case + ".der")
                run([args.osslsigncode, "extract-signature", "-in", output, "-out", der])
                attrs, _ = pkcs7_layout(der.read_bytes(), key.public_key(), digest)
                layout = attrs, None, None
            run([args.osslsigncode, "verify", "-CAfile", cert, "-in", output])
            return layout

        # The same signer-level path and expectations apply to every supported
        # OpenSSL version, without requiring an automatic-time omission API.
        for digest in ("sha1", "sha256"):
            attrs, flags, link = sign("default-" + digest, [], digest)
            assert SIGNING_TIME not in attrs
            assert attrs[OPUS_INFO].encoded == bytes.fromhex("31023000")

        attrs, _, _ = sign("metadata", ["-n", "description", "-i", "https://example.test/"])
        opus = attrs[OPUS_INFO].children()[0].children()
        assert len(opus) == 2
        assert opus[0].children()[0].tag == 0x81
        assert opus[0].children()[0].body == b"description"
        assert opus[1].children()[0].body == b"https://example.test/"
        attrs, _, _ = sign("empty-url", ["-i", ""])
        assert attrs[OPUS_INFO].encoded == bytes.fromhex("31063004a1028000")
        for option in ("-st", "-time"):
            for label, epoch in (("epoch", "0"), ("future", "4294967295"), ("negative", "-1")):
                case = option[1:] + "-" + label
                attrs, _, _ = sign(case, [option, epoch])
                assert SIGNING_TIME not in attrs
                assert (directory / (case + ".exe")).read_bytes() == (directory / "default-sha1.exe").read_bytes()
            run(command + [option], "Usage:")
        attrs, _, _ = sign("both-options", ["-st", "0", "-time", "-1"])
        assert SIGNING_TIME not in attrs
        assert (directory / "both-options.exe").read_bytes() == (directory / "default-sha1.exe").read_bytes()

        verify = [args.osslsigncode, "verify", "-CAfile", cert,
                  "-in", directory / "default-sha1.exe"]
        now = str(int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
        for option in ("-time", "-st"):
            result = run(verify + [option, now])
            assert "deprecated" not in result.stdout, result.stdout
            run(verify + [option, "0"], "certificate is not yet valid")
            run(verify + [option], "Usage:")
            for value in ("", "abc", "1junk", "-1", "18446744073709551615", "-99999999999999999999"):
                run(verify + [option, value], "Invalid verification time")
        # Both spellings set the same option; the last value takes precedence.
        run(verify + ["-time", "0", "-st", now])
        run(verify + ["-st", "0", "-time", now])
        run(verify + ["-time", now, "-st", "0"], "certificate is not yet valid")
        run(verify + ["-st", now, "-time", "0"], "certificate is not yet valid")
        attrs, flags, link = sign("pagehash", ["-ph"])
        assert SIGNING_TIME not in attrs
        assert link.tag == 0xa1 and len(link.body) > 16  # Serialized page-hash object.
        for ext in ("ex_", "msi", "cat", "ps1", "psc1", "mof", "js", "256appx", "512appx"):
            digest = "sha512" if ext == "512appx" else "sha256"
            attrs, _, _ = sign("default-" + ext, [], digest, ext)
            assert SIGNING_TIME not in attrs, ext
            assert attrs[OPUS_INFO].encoded == bytes.fromhex("31023000"), ext
            for option in ("-st", "-time"):
                legacy_attrs, _, _ = sign("legacy-" + option[1:] + "-" + ext, [option, "-1"], digest, ext)
                assert legacy_attrs == attrs, ext
    assert all(path.read_bytes() == data for path, data in originals.items())
    print("No signingTime and legacy -st/-time no-ops verified for all ten formats; "
          "verify -time/-st aliases checked; "
          "content digests, RSA signatures, PE metadata and checksums verified")


if __name__ == "__main__":
    main()
