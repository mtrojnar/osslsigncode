#!/bin/sh

ddays=1461

result_path=$(pwd)
cd $(dirname "$0")
script_path=$(pwd)
cd "${result_path}"

test_result() {
if [ $1 == 0 ]
  then
    printf "Succeeded\n" >> "makecerts.log"
  else
    printf "Failed\n" >> "makecerts.log"
  fi
}

mkdir "tmp/"

# OpenSSL settings
CONF="${script_path}/openssltest.cnf"

if test -n "$1"; then
    OPENSSL="$2/bin/openssl"
    LD_LIBRARY_PATH="$2/lib"
else
    OPENSSL=openssl
fi

mkdir "demoCA/"
touch "demoCA/index.txt"
touch "demoCA/index.txt.attr"
echo 1000 > "demoCA/serial"
date > "makecerts.log"

printf "\nGenerate root CA certificate\n" >> "makecerts.log"
$OPENSSL genrsa -out demoCA/CA.key 1>&2 2>> "makecerts.log"
$OPENSSL req -config $CONF -new -x509 -days $ddays -key demoCA/CA.key -out tmp/CACert.pem \
    -subj "/C=PL/O=osslsigncode/OU=Root CA/CN=CA/emailAddress=CA@example.com" \
    2>> "makecerts.log" 1>&2
test_result $?

printf "\nGenerate CSP Cross-Certificate\n" >> "makecerts.log"
$OPENSSL genrsa -out demoCA/cross.key 1>&2 2>> "makecerts.log"
$OPENSSL req -config $CONF -new -x509 -days $ddays -key demoCA/cross.key -out tmp/crosscert.pem \
    -subj "/C=PL/O=osslsigncode/OU=CSP/CN=crosscert/emailAddress=CA@example.com" \
    2>> "makecerts.log" 1>&2
test_result $?

printf "\nGenerate private RSA encrypted key\n" >> "makecerts.log"
$OPENSSL genrsa -des3 -out demoCA/private.key -passout pass:passme 1>&2 2>> "makecerts.log"
test_result $?
cat demoCA/private.key >> tmp/keyp.pem 2>> "makecerts.log"

printf "\nGenerate private RSA decrypted key\n" >> "makecerts.log"
$OPENSSL rsa -in demoCA/private.key -passin pass:passme -out tmp/key.pem 1>&2 2>> "makecerts.log"
test_result $?

printf "\nGenerate code signing certificate\n" >> "makecerts.log"
$OPENSSL req -config $CONF -new -key demoCA/private.key -passin pass:passme -out demoCA/cert.csr \
    -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CA/CN=localhost/emailAddress=osslsigncode@example.com" \
    2>> "makecerts.log" 1>&2
test_result $?
$OPENSSL ca -config $CONF -batch -days $ddays -in demoCA/cert.csr -out demoCA/cert.cer 1>&2 2>> "makecerts.log"
test_result $?
$OPENSSL x509 -in demoCA/cert.cer -out tmp/cert.pem 1>&2 2>> "makecerts.log"

printf "\nConverting the key to DER format\n" >> "makecerts.log"
$OPENSSL rsa -in tmp/key.pem -outform DER -out tmp/key.der -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?
printf "\nConverting the key to PVK format\n" >> "makecerts.log"
$OPENSSL rsa -in tmp/key.pem -outform PVK -pvk-strong -out tmp/key.pvk -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?
echo "passme" > "password.txt"

printf "\nConverting the certificate to SPC format\n" >> "makecerts.log"
$OPENSSL crl2pkcs7 -nocrl -certfile tmp/cert.pem -outform DER -out tmp/cert.spc 2>> "makecerts.log" 1>&2
test_result $?

printf "\nConverting the certificate to DER format\n" >> "makecerts.log"
openssl x509 -in tmp/cert.pem -outform DER -out tmp/cert.der
test_result $?

printf "\nConverting the certificate and the key into a PKCS#12 container\n" >> "makecerts.log"
$OPENSSL pkcs12 -export -in tmp/cert.pem -inkey tmp/key.pem -out tmp/cert.p12 -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?

# copy new files
if [ -s tmp/CACert.pem ]  && [ -s tmp/crosscert.pem ] && [ -s tmp/cert.pem ] && \
    [ -s tmp/key.pem ] && [ -s tmp/keyp.pem ] && [ -s tmp/key.der ] && [ -s tmp/cert.der ] && \
    [ -s tmp/key.pvk ] && [ -s tmp/cert.spc ] && [ -s tmp/cert.p12 ]
  then
    cp tmp/* ./
    printf "%s\n" "keys & certificates successfully generated"
    printf "%s\n" "./makecerts.sh finished"
    rm -f "makecerts.log"
  else
    printf "%s\n" "./makecerts.sh failed"
    printf "%s\n" "error logs ${result_path}/makecerts.log"
  fi

# remove the working directory
rm -rf "demoCA/"
rm -rf "tmp/"
