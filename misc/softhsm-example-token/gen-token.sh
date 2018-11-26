#!/bin/bash

export PKCS11_MODULE_PATH=/usr/lib/libsofthsm2.so

cat >config.py <<EOF
DEBUG = True
SECRET = "secret1"
PKCS11MODULE = "$PKCS11_MODULE_PATH"
PKCS11PIN = "secret1"
EOF

# initialize the token
softhsm2-util --delete-token --token osslsigncode
softhsm2-util --init-token --free --label osslsigncode --pin secret1 --so-pin secret2

# create and print a key pair
pkcs11-tool --module $PKCS11_MODULE_PATH -l -k --key-type rsa:2048 --id a1b2 --label test --pin secret1
pkcs11-tool --module $PKCS11_MODULE_PATH -l --pin secret1 -O

# create and print a certificate
openssl req -new -x509 -subj "/CN=TEST" -engine pkcs11 -keyform engine -key "pkcs11:token=osslsigncode;object=test;pin-value=secret1" -out test.crt
openssl x509 -inform PEM -outform DER -in test.crt -out test.der
pkcs11-tool --module $PKCS11_MODULE_PATH -l --id a1b2 --label test -y cert -w test.der --pin secret1
