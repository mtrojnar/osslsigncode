#!/usr/bin/python3
"""Make test certificates"""

import os
import datetime
import cryptography

# Explicit imports of cryptography submodules
import cryptography.x509
import cryptography.x509.oid
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs12

# Import classes and functions from the cryptography module
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    CertificateBuilder,
    CertificateRevocationListBuilder,
    CRLDistributionPoints,
    CRLNumber,
    CRLReason,
    DistributionPoint,
    DNSName,
    ExtendedKeyUsage,
    KeyUsage,
    Name,
    NameAttribute,
    NameConstraints,
    random_serial_number,
    RevokedCertificateBuilder,
    ReasonFlags,
    SubjectKeyIdentifier,
    UniformResourceIdentifier
)
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    NameOID
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
    RSAPrivateKey
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat
)
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

try:
    if cryptography.__version__ >= '38.0.0':
        from cryptography.hazmat.primitives.serialization.pkcs12 import PBES
except ImportError:
    pass

RESULT_PATH = os.getcwd()
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")

date_20170101 = datetime.datetime(2017, 1, 1)
date_20180101 = datetime.datetime(2018, 1, 1)
date_20190101 = datetime.datetime(2019, 1, 1)

PASSWORD='passme'


class X509Extensions():
    """Base class for X509 Extensions"""

    def __init__(self, unit_name, cdp_port, cdp_name):
        self.unit_name = unit_name
        self.port = cdp_port
        self.name = cdp_name

    def create_x509_name(self, common_name) -> Name:
        """Return x509.Name"""
        return Name(
            [
                NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Mazovia Province"),
                NameAttribute(NameOID.LOCALITY_NAME, "Warsaw"),
                NameAttribute(NameOID.ORGANIZATION_NAME, "osslsigncode"),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.unit_name),
                NameAttribute(NameOID.COMMON_NAME, common_name)
            ]
        )

    def create_x509_crldp(self) -> CRLDistributionPoints:
        """Return x509.CRLDistributionPoints"""
        return CRLDistributionPoints(
            [
                DistributionPoint(
                    full_name=[UniformResourceIdentifier(
                        "http://127.0.0.1:" + str(self.port) + "/" + str(self.name))
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]
        )

    def create_x509_name_constraints(self) -> NameConstraints:
        """Return x509.NameConstraints"""
        return NameConstraints(
            permitted_subtrees = [DNSName('test.com'), DNSName('test.org')],
            excluded_subtrees = None
        )

class IntermediateCACertificate(X509Extensions):
    """Base class for Intermediate CA certificate"""

    def __init__(self, issuer_cert, issuer_key):
        self.issuer_cert = issuer_cert
        self.issuer_key = issuer_key
        super().__init__("Certification Authority", 0, None)

    def make_cert(self) -> (Certificate, RSAPrivateKey):
        """Generate intermediate CA certificate"""
        key = generate_private_key(public_exponent=65537, key_size=2048)
        key_public = key.public_key()
        authority_key = AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        )
        key_usage = KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        )
        cert = (
            CertificateBuilder()
            .subject_name(self.create_x509_name("Intermediate CA"))
            .issuer_name(self.issuer_cert.subject)
            .public_key(key_public)
            .serial_number(random_serial_number())
            .not_valid_before(date_20180101)
            .not_valid_after(date_20180101 + datetime.timedelta(days=7300))
            .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(SubjectKeyIdentifier.from_public_key(key_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(self.issuer_key, SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "intermediateCA.pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=Encoding.PEM))

        return cert, key


class RootCACertificate(X509Extensions):
    """Base class for Root CA certificate"""

    def __init__(self):
        self.key_usage = KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        )
        super().__init__("Certification Authority", 0, None)

    def make_cert(self) -> (Certificate, RSAPrivateKey):
        """Generate CA certificates"""
        ca_root, root_key = self.make_ca_cert("Trusted Root CA", "CAroot.pem")
        ca_cert, ca_key = self.make_ca_cert("Root CA", "CACert.pem")
        self.make_cross_cert(ca_root, root_key, ca_cert, ca_key)
        return ca_cert, ca_key

    def make_ca_cert(self, common_name, file_name) -> None:
        """Generate self-signed root CA certificate"""
        ca_key = generate_private_key(public_exponent=65537, key_size=2048)
        ca_public = ca_key.public_key()
        authority_key = AuthorityKeyIdentifier.from_issuer_public_key(ca_public)
        name = self.create_x509_name(common_name)
        ca_cert = (
            CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_public)
            .serial_number(random_serial_number())
            .not_valid_before(date_20170101)
            .not_valid_after(date_20170101 + datetime.timedelta(days=7300))
            .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(self.key_usage, critical=True)
            .sign(ca_key, SHA256())
        )
        file_path=os.path.join(CERTS_PATH, file_name)
        with open(file_path, mode="wb") as file:
            file.write(ca_cert.public_bytes(encoding=Encoding.PEM))
        return ca_cert, ca_key

    def make_cross_cert(self, ca_root, root_key, ca_cert, ca_key) -> None:
        """Generate cross-signed root CA certificate"""
        ca_public = ca_key.public_key()
        authority_key = AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_root.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        )
        ca_cross = (
            CertificateBuilder()
            .subject_name(ca_cert.subject)
            .issuer_name(ca_root.subject)
            .public_key(ca_public)
            .serial_number(ca_cert.serial_number)
            .not_valid_before(date_20180101)
            .not_valid_after(date_20180101 + datetime.timedelta(days=7300))
            .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(self.key_usage, critical=True)
            .sign(root_key, SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "CAcross.pem")
        with open(file_path, mode="wb") as file:
            file.write(ca_cross.public_bytes(encoding=Encoding.PEM))

    def write_key(self, key, file_name) -> None:
        """Write a private RSA key"""
        # Write password
        file_path = os.path.join(CERTS_PATH, "password.txt")
        with open(file_path, mode="w", encoding="utf-8") as file:
            file.write("{}".format(PASSWORD))

        # Write encrypted key in PEM format
        file_path = os.path.join(CERTS_PATH, file_name + "p.pem")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(PASSWORD.encode())
            )
        )
        # Write decrypted key in PEM format
        file_path = os.path.join(CERTS_PATH, file_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )
        # Write the key in DER format
        file_path = os.path.join(CERTS_PATH, file_name + ".der")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )


class TSARootCACertificate(X509Extensions):
    """Base class for TSA certificates"""

    def __init__(self):
        super().__init__("Timestamp Authority Root CA", 0, None)

    def make_cert(self) -> (Certificate, RSAPrivateKey):
        """Generate a Time Stamp Authority certificate"""
        ca_key = generate_private_key(public_exponent=65537, key_size=2048)
        ca_public = ca_key.public_key()
        authority_key = AuthorityKeyIdentifier.from_issuer_public_key(ca_public)
        name = self.create_x509_name("TSA Root CA")
        key_usage = KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        )
        ca_cert = (
            CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_public)
            .serial_number(random_serial_number())
            .not_valid_before(date_20170101)
            .not_valid_after(date_20170101 + datetime.timedelta(days=7300))
            .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(ca_key, SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "TSACA.pem")
        with open(file_path, mode="wb") as file:
            file.write(ca_cert.public_bytes(encoding=Encoding.PEM))

        return ca_cert, ca_key

    def write_key(self, key, file_name) -> None:
        """Write decrypted private RSA key into PEM format"""
        file_path = os.path.join(CERTS_PATH, file_name + ".key")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )


class LeafCertificate(X509Extensions):
    """Base class for a leaf certificate"""

    def __init__(self, issuer_cert, issuer_key, unit_name, common_name, cdp_port, cdp_name):
        #pylint: disable=too-many-arguments
        self.issuer_cert = issuer_cert
        self.issuer_key = issuer_key
        self.common_name = common_name
        super().__init__(unit_name, cdp_port, cdp_name)

    def make_cert(self, public_key, not_before, days) -> Certificate:
        """Generate a leaf certificate"""
        authority_key = AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        )
        extended_key_usage = ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CODE_SIGNING]
        )
        cert = (
            CertificateBuilder()
            .subject_name(self.create_x509_name(self.common_name))
            .issuer_name(self.issuer_cert.subject)
            .public_key(public_key)
            .serial_number(random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_before + datetime.timedelta(days=days))
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(extended_key_usage, critical=False)
            .add_extension(self.create_x509_crldp(), critical=False)
            .sign(self.issuer_key, SHA256())
        )
        # Write PEM file and attach intermediate certificate
        file_path = os.path.join(CERTS_PATH, self.common_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=Encoding.PEM))
            file.write(self.issuer_cert.public_bytes(encoding=Encoding.PEM))

        return cert

    def revoke_cert(self, serial_number, file_name) -> None:
        """Revoke a certificate"""
        revoked = (
            RevokedCertificateBuilder()
            .serial_number(serial_number)
            .revocation_date(date_20190101)
            .add_extension(CRLReason(ReasonFlags.superseded), critical=False)
            .build()
        )
        # Generate CRL
        authority_key = AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        )
        crl = (
            CertificateRevocationListBuilder()
            .issuer_name(self.issuer_cert.subject)
            .last_update(date_20190101)
            .next_update(date_20190101 + datetime.timedelta(days=7300))
            .add_extension(authority_key, critical=False)
            .add_extension(CRLNumber(4097), critical=False)
            .add_revoked_certificate(revoked)
            .sign(self.issuer_key, SHA256())
        )
        # Write CRL file
        file_path = os.path.join(CERTS_PATH, file_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(crl.public_bytes(encoding=Encoding.PEM))

        file_path = os.path.join(CERTS_PATH, file_name + ".der")
        with open(file_path, mode="wb") as file:
            file.write(crl.public_bytes(encoding=Encoding.DER))


class LeafCACertificate(LeafCertificate):
    """Base class for a leaf certificate"""

    def __init__(self, issuer_cert, issuer_key, common, cdp_port):
        super().__init__(issuer_cert, issuer_key, "CSP", common, cdp_port, "intermediateCA")


class LeafTSACertificate(LeafCertificate):
    """Base class for a TSA leaf certificate"""

    def __init__(self, issuer_cert, issuer_key, common, cdp_port):
        self.issuer_cert = issuer_cert
        self.issuer_key = issuer_key
        self.common_name = common
        super().__init__(issuer_cert, issuer_key, "Timestamp Root CA", common, cdp_port, "TSACA")

    def make_cert(self, public_key, not_before, days) -> Certificate:
        """Generate a TSA leaf certificate"""

        authority_key = AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(SubjectKeyIdentifier).value
        )

        # The TSA signing certificate must have exactly one extended key usage
        # assigned to it: timeStamping. The extended key usage must also be critical,
        # otherwise the certificate is going to be refused.
        extended_key_usage = ExtendedKeyUsage(
            [ExtendedKeyUsageOID.TIME_STAMPING]
        )
        cert = (
            CertificateBuilder()
            .subject_name(self.create_x509_name(self.common_name))
            .issuer_name(self.issuer_cert.subject)
            .public_key(public_key)
            .serial_number(random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_before + datetime.timedelta(days=days))
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(extended_key_usage, critical=True)
            .add_extension(self.create_x509_crldp(), critical=False)
            .add_extension(self.create_x509_name_constraints(), critical=False)
            .sign(self.issuer_key, SHA256())
        )
        # Write PEM file and attach intermediate certificate
        file_path = os.path.join(CERTS_PATH, self.common_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=Encoding.PEM))
            file.write(self.issuer_cert.public_bytes(encoding=Encoding.PEM))

        return cert


class CertificateMaker():
    """Base class for test certificates"""

    def __init__(self, cdp_port, logs):
        self.cdp_port = cdp_port
        self.logs = logs

    def make_certs(self) -> None:
        """Make test certificates"""
        try:
            self.make_ca_certs()
            self.make_tsa_certs()
            logs = os.path.join(CERTS_PATH, "./cert.log")
            with open(logs, mode="w", encoding="utf-8") as file:
                file.write("Test certificates generation succeeded")
        except Exception as err: # pylint: disable=broad-except
            with open(self.logs, mode="a", encoding="utf-8") as file:
                file.write("Error: {}".format(err))

    def make_ca_certs(self):
        """Make test certificates"""

        # Generate root CA certificate
        root = RootCACertificate()
        ca_cert, ca_key = root.make_cert()

        # Generate intermediate root CA certificate
        intermediate = IntermediateCACertificate(ca_cert, ca_key)
        issuer_cert, issuer_key = intermediate.make_cert()

        # Generate private RSA key
        private_key = generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        root.write_key(key=private_key, file_name="key")

        # Generate expired certificate
        expired = LeafCACertificate(issuer_cert, issuer_key, "expired", self.cdp_port)
        expired.make_cert(public_key, date_20180101, 365)

        # Generate revoked certificate
        revoked = LeafCACertificate(issuer_cert, issuer_key, "revoked", self.cdp_port)
        cert = revoked.make_cert(public_key, date_20180101, 5840)
        revoked.revoke_cert(cert.serial_number, "CACertCRL")

        # Generate code signing certificate
        signer = LeafCACertificate(issuer_cert, issuer_key, "cert", self.cdp_port)
        cert = signer.make_cert(public_key, date_20180101, 5840)

        # Write a certificate and a key into PKCS#12 container
        self.write_pkcs12_container(
            cert=cert,
            key=private_key,
            issuer=issuer_cert
        )

        # Write DER file and attach intermediate certificate
        file_path = os.path.join(CERTS_PATH, "cert.der")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=Encoding.DER))

    def make_tsa_certs(self):
        """Make test TSA certificates"""

        # Time Stamp Authority certificate
        root = TSARootCACertificate()
        issuer_cert, issuer_key = root.make_cert()

        # Generate private RSA key
        private_key = generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        root.write_key(key=private_key, file_name="TSA")

        # Generate revoked TSA certificate
        revoked = LeafTSACertificate(issuer_cert, issuer_key, "TSA_revoked", self.cdp_port)
        cert = revoked.make_cert(public_key, date_20180101, 7300)
        revoked.revoke_cert(cert.serial_number, "TSACertCRL")

        # Generate TSA certificate
        signer = LeafTSACertificate(issuer_cert, issuer_key, "TSA", self.cdp_port)
        cert = signer.make_cert(public_key, date_20180101, 7300)

        # Save the chain to be included in the TSA response
        file_path = os.path.join(CERTS_PATH, "tsa-chain.pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=Encoding.PEM))
            file.write(issuer_cert.public_bytes(encoding=Encoding.PEM))


    def write_pkcs12_container(self, cert, key, issuer) -> None:
        """Write a certificate and a key into a PKCS#12 container"""

        # Set an encryption algorithm
        if cryptography.__version__ >= "38.0.0":
            # For OpenSSL legacy mode use the default algorithm for certificate
            # and private key encryption: DES-EDE3-CBC (vel 3DES_CBC)
            # pylint: disable=no-member
            encryption = (
                PrivateFormat.PKCS12.encryption_builder()
                .key_cert_algorithm(PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .kdf_rounds(5000)
                .build(PASSWORD.encode())
            )
        else:
            encryption = BestAvailableEncryption(PASSWORD.encode())

        # Generate PKCS#12 struct
        pkcs12 = serialize_key_and_certificates(
            name=b'certificate',
            key=key,
            cert=cert,
            cas=(issuer,),
            encryption_algorithm=encryption
        )

        # Write into a PKCS#12 container
        file_path = os.path.join(CERTS_PATH, "cert.p12")
        with open(file_path, mode="wb") as file:
            file.write(pkcs12)


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
