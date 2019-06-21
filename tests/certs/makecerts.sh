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

printf "\nGenerating a self-signed certificate " >> "makecerts.log"
$OPENSSL req -config $CONF -new -x509 -days $ddays -keyout tmp/key.pem -out tmp/cert.pem \
    -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CA/CN=localhost/emailAddress=osslsigncode@example.com" \
     2>> "makecerts.log" 1>&2
test_result $?

printf "\nConverting the key to PEM format (with password)\n" >> "makecerts.log"
$OPENSSL rsa -in tmp/key.pem -out tmp/keyp.pem -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?
printf "\nConverting the key to DER format\n" >> "makecerts.log"
$OPENSSL rsa -in tmp/key.pem -outform DER -out tmp/key.der -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?
printf "\nConverting the key to PVK format\n" >> "makecerts.log"
$OPENSSL rsa -in tmp/key.pem -outform PVK -pvk-strong -out tmp/key.pvk -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?

printf "\nConverting the certificate to SPC format\n" >> "makecerts.log"
$OPENSSL crl2pkcs7 -nocrl -certfile tmp/cert.pem -outform DER -out tmp/cert.spc 2>> "makecerts.log" 1>&2
test_result $?

printf "\nConverting the certificate and the key into a PKCS#12 container\n" >> "makecerts.log"
$OPENSSL pkcs12 -export -in tmp/cert.pem -inkey tmp/key.pem -out tmp/cert.p12 -passout pass:passme 2>> "makecerts.log" 1>&2
test_result $?

# copy new files
if [ -s tmp/cert.pem ] && [ -s tmp/key.pem ] && [ -s tmp/keyp.pem ] && [ -s tmp/key.der ] \
    && [ -s tmp/key.pvk ] && [ -s tmp/cert.spc ]  && [ -s tmp/cert.p12 ]
  then
    cp tmp/* ./
    printf "%s\n" "keys & certificates successfully generated"
    printf "%s\n" "./makecerts.sh finished"
    rm -f "makecerts.log"
  else
    printf "%s\n" "./makecerts.sh failed"
    printf "%s\n" "error logs ${result_path}/makecerts.log"
  fi

rm -rf "tmp/"
