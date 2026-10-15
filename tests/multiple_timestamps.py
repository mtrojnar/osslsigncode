#!/usr/bin/env python3
"""End-to-end timestamp tests, using only local keys and a loopback TSA.

The small DER reader edits unsigned attributes only, allowing fixtures with
multiple values, repeated attributes, and malformed timestamp values.
"""

import base64
import copy
import datetime
import http.server
import pathlib
import struct
import subprocess
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class DER:
    """Single-octet-tag DER node (sufficient for these PKCS#7 fixtures)."""

    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def encode(self):
        value = self.value
        if isinstance(value, list):
            value = b"".join(item.encode() for item in value)
        size = len(value)
        length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length() + 7) // 8, "big")
        if size >= 128:
            length = bytes([128 + len(length)]) + length
        return bytes([self.tag]) + length + value

    @classmethod
    def parse(cls, data):
        tag, size = data[:2]
        offset = 2
        if size & 128:
            count = size & 127
            size = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        end = offset + size
        assert end <= len(data)
        value = data[offset:end]
        if tag & 32:
            children = []
            while value:
                child, value = cls.parse(value)
                children.append(child)
            value = children
        return cls(tag, value), data[end:]


def decode(data):
    node, rest = DER.parse(data)
    assert not rest
    return node


def signed_data(node):
    return node.value[1].value[0]


def signer_info(node):
    return signed_data(node).value[-1].value[0]


RFC3161 = bytes.fromhex("2b060104018237030301")
COUNTERSIGNATURE = bytes.fromhex("2a864886f70d010906")
SIGNING_TIME = bytes.fromhex("2a864886f70d010905")


def timestamps(node):
    si = signer_info(node)
    if si.value[-1].tag != 0xA1:
        return []
    return [attr for attr in si.value[-1].value
            if attr.value[0].value in (RFC3161, COUNTERSIGNATURE)]


def run(*args, expected=0):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, check=False)
    codes = (expected,) if isinstance(expected, int) else expected
    assert result.returncode in codes, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout + result.stderr


def certificate(directory, name, eku, expires=2038):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2018, 1, 1))
            .not_valid_after(datetime.datetime(expires, 1, 1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
            .sign(key, hashes.SHA256()))
    (directory / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / (name + ".key")).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key, cert


def main():
    exe, unsigned = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="multiple-timestamps-") as tmp:
        directory = pathlib.Path(tmp)
        certificate(directory, "code", ExtendedKeyUsageOID.CODE_SIGNING)
        certificate(directory, "short", ExtendedKeyUsageOID.CODE_SIGNING, 2020)
        tsa_key, tsa_cert = certificate(directory, "tsa", ExtendedKeyUsageOID.TIME_STAMPING)
        certificate(directory, "other", ExtendedKeyUsageOID.TIME_STAMPING)
        sequence = 0

        def output(suffix=".exe"):
            nonlocal sequence
            sequence += 1
            return directory / (str(sequence) + suffix)

        def sign(name="code", *extra, source=unsigned):
            dest = output(source.suffix)
            run(exe, "sign", "-certs", directory / (name + ".pem"),
                "-key", directory / (name + ".key"), *extra, "-in", source, "-out", dest)
            return dest

        def add(source, *extra, expected=0):
            dest = output(source.suffix)
            run(exe, "add", *extra, "-in", source, "-out", dest, expected=expected)
            if expected != 0:
                assert not dest.exists(), "Failed timestamping left a partial output"
            return dest

        def builtin(name="tsa", time="1556668800"):
            return ("-TSA-certs", directory / (name + ".pem"),
                    "-TSA-key", directory / (name + ".key"), "-TSA-time", time)

        def extract(source):
            dest = output(".der")
            run(exe, "extract-signature", "-in", source, "-out", dest)
            return decode(dest.read_bytes())

        def verify(source, expected=0, ignore=False, ca="code", successes=None, failures=None):
            text = run(exe, "verify", "-CAfile", directory / (ca + ".pem"),
                       "-TSA-CAfile", directory / "tsa.pem", "-time", "1567296000",
                       *(["-ignore-timestamp"] if ignore else []),
                       "-in", source, expected=expected)
            if successes is not None:
                assert text.count("Timestamp Server Signature verification: ok") == successes, text
            if failures is not None:
                assert text.count("Timestamp Server Signature verification: failed") == failures, text
            return text

        plain = sign()
        verify(plain)
        first = add(plain, *builtin())
        second = add(first, *builtin(time="1567296000"))
        attrs = timestamps(extract(second))
        assert len(attrs) == 1 and len(attrs[0].value[1].value) == 2
        verify(second, successes=2)
        for source in sorted(unsigned.parent.glob("unsigned.*")):
            if source != unsigned:
                stamped = sign("code", *builtin(), source=source)
                verify(add(stamped, *builtin(time="1567296000")), successes=2)

        # Untrusted timestamps never mask a trusted one, regardless of add order.
        bad = add(plain, *builtin("other"))
        verify(bad, expected=1, failures=1)
        verify(bad, ignore=True)
        verify(add(first, *builtin("other")), successes=1, failures=1)
        verify(add(bad, *builtin()), successes=1, failures=1)
        verify(add(bad, *builtin("other", "1567296000")), expected=1, failures=2)
        nested = output()
        run(exe, "sign", "-nest", "-certs", directory / "code.pem",
            "-key", directory / "code.key", "-in", bad, "-out", nested)
        verify(nested, failures=1)  # A separate valid signature still suffices.
        nested = add(nested, "-index", "1", *builtin())
        verify(add(nested, "-index", "1", *builtin(time="1567296000")), successes=2, failures=1)

        # A trusted TSA is insufficient: the code certificate must be valid at
        # that particular timestamp. Try alternatives, not just the first TSA.
        short = sign("short")
        late = add(short, *builtin(time="1609459200"))
        verify(late, expected=1, ca="short", successes=1)
        verify(add(late, *builtin()), ca="short", successes=2)
        early = add(short, *builtin())
        verify(add(early, *builtin(time="1609459200")), ca="short", successes=2)

        # Directly write PE certificate tables to avoid attach-signature's
        # verification policy interfering with deliberately invalid fixtures.
        def fixture(node):
            data = bytearray(plain.read_bytes())
            pe = struct.unpack_from("<I", data, 0x3C)[0]
            optional = pe + 24
            magic = struct.unpack_from("<H", data, optional)[0]
            security = optional + (112 if magic == 0x20B else 96) + 4 * 8
            offset, _ = struct.unpack_from("<II", data, security)
            der = node.encode()
            size = (len(der) + 8 + 7) & ~7
            struct.pack_into("<II", data, security, offset, size)
            data[offset:] = struct.pack("<IHH", size, 0x200, 2) + der + bytes(size - 8 - len(der))
            dest = output()
            dest.write_bytes(data)
            return dest

        # A trusted token for another signature must fail message-imprint
        # validation, but must not prevent trying a correctly bound token.
        node = extract(first)
        foreign = timestamps(extract(early))[0].value[1].value
        timestamps(node)[0].value[1].value = foreign
        verify(fixture(node), expected=1, failures=1)
        timestamps(node)[0].value[1].value += timestamps(extract(first))[0].value[1].value
        verify(fixture(node), successes=1, failures=1)

        for broken_index in (0, 1):
            node = extract(second)
            values = timestamps(node)[0].value[1].value
            signature = signer_info(values[broken_index]).value[-1]
            signature.value = bytes([signature.value[0] ^ 1]) + signature.value[1:]
            verify(fixture(node), successes=1, failures=1)
            # Exercise repeated attributes as well as multiple SET values.
            attr = timestamps(node)[0]
            signer_info(node).value[-1].value = [DER(0x30, [copy.deepcopy(attr.value[0]), DER(0x31, [v])])
                                                for v in values]
            verify(fixture(node), successes=1, failures=1)

        for malformed in (DER(0x30, []), DER(4, b"invalid")):
            node = extract(first)
            timestamps(node)[0].value[1].value = [malformed]
            verify(fixture(node), expected=1, failures=1)
            verify(fixture(node), ignore=True)
            timestamps(node)[0].value[1].value += timestamps(extract(first))[0].value[1].value
            verify(fixture(node), successes=1, failures=1)
        node = extract(first)
        timestamps(node)[0].value[1].value = []
        verify(fixture(node), expected=1)

        # A loopback service returns a real legacy Authenticode countersignature
        # or an RFC3161 response, and can deliberately fail selected requests.
        requests = []
        (directory / "serial").write_text("01\n", encoding="ascii")
        config = directory / "tsa.cnf"
        config.write_text(f"""[tsa]
default_tsa = tsa_config
[tsa_config]
serial = {(directory / 'serial').as_posix()}
signer_cert = {(directory / 'tsa.pem').as_posix()}
certs = {(directory / 'tsa.pem').as_posix()}
signer_key = {(directory / 'tsa.key').as_posix()}
signer_digest = sha256
default_policy = 1.2.3.4
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
""", encoding="utf-8")

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                requests.append(self.path)
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/fail":
                    self.send_error(500)
                    return
                if self.path == "/legacy":
                    request = decode(base64.b64decode(body))
                    digest = request.value[1].value[1].value[0].value
                    response = decode(pkcs7.PKCS7SignatureBuilder().set_data(digest)
                                      .add_signer(tsa_cert, tsa_key, hashes.SHA256())
                                      .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
                    si = signer_info(response)
                    attrs = si.value[3].value
                    for attr in attrs:
                        if attr.value[0].value == SIGNING_TIME:
                            attr.value[1].value = [DER(23, b"190501000000Z")]
                    attrs.sort(key=lambda a: a.encode())
                    si.value[-1].value = tsa_key.sign(DER(0x31, attrs).encode(), padding.PKCS1v15(), hashes.SHA256())
                    response = base64.b64encode(response.encode())
                    content_type = "application/octet-stream"
                else:
                    query, reply = directory / "query.tsq", directory / "reply.tsr"
                    query.write_bytes(body)
                    run("openssl", "ts", "-reply", "-config", config, "-queryfile", query, "-out", reply)
                    response = reply.read_bytes()
                    content_type = "application/timestamp-reply"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            for flag, endpoint in (("-ts", "/rfc"), ("-t", "/legacy")):
                requests.clear()
                fallback = sign("code", flag, url + "/fail", flag, url + endpoint, flag, url + "/fail")
                assert requests == ["/fail", endpoint], requests
                verify(fallback, successes=1)
                requests.clear()
                multiple = sign("code", "-timestamp-all", flag, url + endpoint, flag, url + endpoint)
                assert requests == [endpoint, endpoint], requests
                verify(multiple, successes=2)
                node = extract(multiple)
                token = timestamps(node)[0].value[1].value[0]
                si = signer_info(token) if flag == "-ts" else token
                signature = si.value[-1]
                signature.value = bytes([signature.value[0] ^ 1]) + signature.value[1:]
                verify(fixture(node), successes=1, failures=1)
                for paths in (("/fail", endpoint), (endpoint, "/fail")):
                    add(plain, "-timestamp-all", flag, url + paths[0], flag, url + paths[1], expected=1)
            mixed = sign("code", "-timestamp-all", "-t", url + "/legacy", "-ts", url + "/rfc")
            assert len(timestamps(extract(mixed))) == 2
            verify(mixed, successes=2)
            # A bad value in either protocol must not hide the other protocol.
            for broken_oid in (RFC3161, COUNTERSIGNATURE):
                node = extract(mixed)
                attr = next(a for a in timestamps(node) if a.value[0].value == broken_oid)
                attr.value[1].value = [DER(0x30, [])]
                verify(fixture(node), successes=1, failures=1)
            verify(add(first, "-t", url + "/legacy"), successes=2)
            # main returns -1 for invalid options (platform-specific exit code).
            add(plain, "-t", url + "/legacy", "-ts", url + "/rfc", expected=(255, 4294967295))
            for flag in ("-t", "-ts"):
                requests.clear()
                add(plain, "-timestamp-all", *([flag, url + "/fail"] * 257), expected=(255, 4294967295))
                assert not requests, "Too many servers should be rejected before timestamping"
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
    print("Multiple timestamp signing and verification tests passed")


if __name__ == "__main__":
    main()
