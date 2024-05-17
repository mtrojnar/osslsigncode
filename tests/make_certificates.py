#!/usr/bin/python3
"""Make test certificates"""

import os
import datetime
import cryptography
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

RESULT_PATH = os.getcwd()
CERTS_PATH = os.path.join(RESULT_PATH, "./Testing/certs/")
LOGS_PATH = os.path.join(RESULT_PATH, "./Testing/logs/")

date_20170101 = datetime.datetime(2017, 1, 1)
date_20180101 = datetime.datetime(2018, 1, 1)
date_20190101 = datetime.datetime(2019, 1, 1)

PASSWORD='passme'

class MakeCertificates():
    """Base class for CA certificates"""

    def __init__(self, port):
        self.port = port
        self.issuer_cert = None
        self.issuer_key = None

    def make_certs(self):
        """Make test certificates"""

        # Generate CA certificates
        ca_cert, ca_key = self.create_ca()
        self.issuer_cert, self.issuer_key = self.create_intermediate(ca_cert, ca_key)

        # Generate private RSA key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.write_key(key=private_key, file_name="key")

        # Generate expired certificate
        self.create_cert(
            public_key = private_key.public_key(),
            common_name="expired",
            not_before=date_20180101,
            not_after=date_20180101 + datetime.timedelta(days=365)
        )

        # Generate revoked certificate
        cert = self.create_cert(
            public_key = private_key.public_key(),
            common_name="revoked",
            not_before=date_20180101,
            not_after=date_20180101 + datetime.timedelta(days=5840)
        )
        self.revoke_cert(
            serial_number=cert.serial_number,
            file_name="CACertCRL"
        )

        # Generate code signing certificate
        cert = self.create_cert(
            public_key = private_key.public_key(),
            common_name="cert",
            not_before=date_20180101,
            not_after=date_20180101 + datetime.timedelta(days=5840)
        )

        # Write a certificate and a key into PKCS#12 container
        self.write_pkcs12_container(
            cert=cert,
            key=private_key
        )

        # Write DER file and attach intermediate certificate
        file_path = os.path.join(CERTS_PATH, "cert.der")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=serialization.Encoding.DER))


    def write_key(self, key, file_name) -> None:
        """Write a private RSA key."""

        # Write password
        file_path = os.path.join(CERTS_PATH, "password.txt")
        with open(file_path, mode="w", encoding="utf-8") as file:
            file.write("{}".format(PASSWORD))

        # Write encrypted key in PEM format
        file_path = os.path.join(CERTS_PATH, file_name + "p.pem")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode())
            )
        )
        # Write decrypted key in PEM format
        file_path = os.path.join(CERTS_PATH, file_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        # Write the key in DER format
        file_path = os.path.join(CERTS_PATH, file_name + ".der")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


    def write_pkcs12_container(self, cert, key) -> None:
        """Write a certificate and a key into PKCS#12 container."""

        # Set an encryption algorithm
        if cryptography.__version__ >= "38.0.0":
            # For OpenSSL legacy mode use the default algorithm for certificate
            # and private key encryption: DES-EDE3-CBC (vel 3DES_CBC)
            # pylint: disable=no-member
            encryption = (
                serialization.PrivateFormat.PKCS12.encryption_builder()
                .key_cert_algorithm(serialization.pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .kdf_rounds(5000)
                .build(PASSWORD.encode())
            )
        else:
            encryption = serialization.BestAvailableEncryption(PASSWORD.encode())

        # Generate PKCS#12 struct
        pkcs12 = serialization.pkcs12.serialize_key_and_certificates(
            name=b'certificate',
            key=key,
            cert=cert,
            cas=(self.issuer_cert,),
            encryption_algorithm=encryption
        )

        # Write into a PKCS#12 container
        file_path = os.path.join(CERTS_PATH, "cert.p12")
        with open(file_path, mode="wb") as file:
            file.write(pkcs12)


    def create_x509_name(self, unit, common) -> x509.Name:
        """Return x509.Name."""

        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Mazovia Province"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Warsaw"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "osslsigncode"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit),
                x509.NameAttribute(NameOID.COMMON_NAME, common)
            ]
        )
        return name

    def create_ca(self) -> (x509.Certificate, rsa.RSAPrivateKey):
        """Root CA certificates."""

        key_usage = x509.KeyUsage(
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

        # Generate Self-signed root CA certificate
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_public = root_key.public_key()
        authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_public)
        name = self.create_x509_name(
            unit="Certification Authority",
            common="Trusted Root CA"
        )
        ca_root = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(root_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(date_20170101)
            .not_valid_after(date_20170101 + datetime.timedelta(days=7300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(root_key, hashes.SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "CAroot.pem")
        with open(file_path, mode="wb") as file:
            file.write(ca_root.public_bytes(encoding=serialization.Encoding.PEM))

        # Generate Self-signed root CA certificate
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_public = ca_key.public_key()
        authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public)
        name = self.create_x509_name(
            unit="Certification Authority",
            common="Root CA"
        )
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(date_20170101)
            .not_valid_after(date_20170101 + datetime.timedelta(days=7300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "CACert.pem")
        with open(file_path, mode="wb") as file:
            file.write(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))

        # Generate Cross-signed root CA certificate
        authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        )
        ca_cross = (
            x509.CertificateBuilder()
            .subject_name(ca_cert.subject)
            .issuer_name(ca_root.subject)
            .public_key(ca_public)
            .serial_number(ca_cert.serial_number)
            .not_valid_before(date_20180101)
            .not_valid_after(date_20180101 + datetime.timedelta(days=7300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(root_key, hashes.SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "CAcross.pem")
        with open(file_path, mode="wb") as file:
            file.write(ca_cross.public_bytes(encoding=serialization.Encoding.PEM))

        return ca_cert, ca_key


    def create_intermediate(self, ca_cert, ca_key) -> (x509.Certificate, rsa.RSAPrivateKey):
        """Intermediate CA certificate."""

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_public = key.public_key()
        name = self.create_x509_name(
            unit="Certification Authority",
            common="Intermediate CA"
        )
        key_usage = x509.KeyUsage(
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
        authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_cert.subject)
            .public_key(key_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(date_20180101)
            .not_valid_after(date_20180101 + datetime.timedelta(days=7300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "intermediateCA.pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        return cert, key


    def create_cert(self, public_key, common_name, not_before, not_after) -> x509.Certificate:
        """Generate a certificate."""

        authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        )
        extended_key_usage = x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]
        )
        crldp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "http://127.0.0.1:" + str(self.port) + "/intermediateCA")
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]
        )
        name = self.create_x509_name(
            unit="CSP",
            common=common_name
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(self.issuer_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(extended_key_usage, critical=False)
            .add_extension(crldp, critical=False)
            .sign(self.issuer_key, hashes.SHA256())
        )
        # Write PEM file and attach intermediate certificate
        file_path = os.path.join(CERTS_PATH, common_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            file.write(self.issuer_cert.public_bytes(encoding=serialization.Encoding.PEM))

        return cert


    def revoke_cert(self, serial_number, file_name) -> None:
        """Generate a certificate."""

        # Revoke certificate
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_number)
            .revocation_date(date_20190101)
            .add_extension(x509.CRLReason(x509.ReasonFlags.superseded), critical=False)
            .build()
        )
        # Generate CRL
        authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.issuer_cert.subject)
            .last_update(date_20190101)
            .next_update(date_20190101 + datetime.timedelta(days=7300))
            .add_extension(authority_key, critical=False)
            .add_extension(x509.CRLNumber(4097), critical=False)
            .add_revoked_certificate(revoked)
            .sign(self.issuer_key, hashes.SHA256())
        )
        # Write CRL file
        file_path = os.path.join(CERTS_PATH, file_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(crl.public_bytes(encoding=serialization.Encoding.PEM))

        file_path = os.path.join(CERTS_PATH, file_name + ".der")
        with open(file_path, mode="wb") as file:
            file.write(crl.public_bytes(encoding=serialization.Encoding.DER))


class MakeTSACertificates(MakeCertificates):
    """Base class for TSA certificates"""

    def __init__(self, port):
        super().__init__(port)
        self.port = port
        # Time Stamp Authority certificate
        self.issuer_cert, self.issuer_key = self.create_ca()

    def make_certs(self):
        """Make test certificates"""

        # Generate private RSA key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.write_key(key=private_key, file_name="TSA")

        # Generate revoked TSA certificate
        cert = self.create_cert(
            public_key = private_key.public_key(),
            common_name="TSA_revoked",
            not_before=date_20180101,
            not_after=date_20180101 + datetime.timedelta(days=7300)
        )
        self.revoke_cert(
            serial_number=cert.serial_number,
            file_name="TSACertCRL"
        )

        # Generate TSA certificate
        cert = self.create_cert(
            public_key = private_key.public_key(),
            common_name="TSA",
            not_before=date_20180101,
            not_after=date_20180101 + datetime.timedelta(days=7300)
        )

        # Save the chain to be included in the TSA response
        file_path = os.path.join(CERTS_PATH, "tsa-chain.pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            file.write(self.issuer_cert.public_bytes(encoding=serialization.Encoding.PEM))


    def create_ca(self) -> (x509.Certificate, rsa.RSAPrivateKey):
        """Time Stamp Authority certificate."""

        # Generate private RSA key
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_public = ca_key.public_key()
        authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public)
        name = self.create_x509_name(
            unit="Timestamp Authority Root CA",
            common="TSA Root CA"
        )
        key_usage = x509.KeyUsage(
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
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(date_20170101)
            .not_valid_after(date_20170101 + datetime.timedelta(days=7300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_public), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(key_usage, critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        file_path=os.path.join(CERTS_PATH, "TSACA.pem")
        with open(file_path, mode="wb") as file:
            file.write(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))

        return ca_cert, ca_key


    def create_cert(self, public_key, common_name, not_before, not_after) -> x509.Certificate:
        """Generate TSA certificate."""

        authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            self.issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        )

        # The TSA signing certificate must have exactly one extended key usage
        # assigned to it: timeStamping. The extended key usage must also be critical,
        # otherwise the certificate is going to be refused.
        extended_key_usage = x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]
        )
        crldp = x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "http://127.0.0.1:" + str(self.port) + "/TSACA")
                    ],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None
                )
            ]
        )
        name_constraints = x509.NameConstraints(
            permitted_subtrees = [x509.DNSName('test.com'), x509.DNSName('test.org')],
            excluded_subtrees = None
        )
        name = self.create_x509_name(
            unit="Timestamp Root CA",
            common=common_name
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(self.issuer_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(authority_key, critical=False)
            .add_extension(extended_key_usage, critical=True)
            .add_extension(crldp, critical=False)
            .add_extension(name_constraints, critical=False)
            .sign(self.issuer_key, hashes.SHA256())
        )
        # Write PEM file and attach intermediate certificate
        file_path = os.path.join(CERTS_PATH, common_name + ".pem")
        with open(file_path, mode="wb") as file:
            file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            file.write(self.issuer_cert.public_bytes(encoding=serialization.Encoding.PEM))

        return cert


    def write_key(self, key, file_name) -> None:
        """Write a private RSA key."""

        # Write decrypted private RSA key into PEM format
        file_path = os.path.join(CERTS_PATH, file_name + ".key")
        with open(file_path, mode="wb") as file:
            file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


class MakeTestCertificates():
    """Base class for CA certificates"""

    def __init__(self, port):
        self.port = port
        self.logs = os.path.join(LOGS_PATH, "./server.log")
        self.make_certs()

    def make_certs(self) -> None:
        """Make test certificates"""

        try:
            root_ca = MakeCertificates(self.port)
            root_ca.make_certs()
            tsa_ca = MakeTSACertificates(self.port)
            tsa_ca.make_certs()
            logs = os.path.join(CERTS_PATH, "./cert.log")
            with open(logs, mode="w", encoding="utf-8") as file:
                file.write("Test certificates generation succeeded")
        except Exception as err: # pylint: disable=broad-except
            with open(self.logs, mode="a", encoding="utf-8") as file:
                file.write("Error: {}".format(err))


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
