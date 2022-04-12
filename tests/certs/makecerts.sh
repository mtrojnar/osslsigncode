#!/bin/sh

result=0

test_result() {
  if test "$1" -eq 0
    then
      printf "Succeeded\n" >> "makecerts.log"
    else
      printf "Failed\n" >> "makecerts.log"
    fi
}

make_certs() {
  password=passme
  result_path=$(pwd)
  cd $(dirname "$0")
  script_path=$(pwd)
  cd "${result_path}"
  mkdir "tmp/"

# OpenSSL settings
  CONF="${script_path}/openssl_intermediate.cnf"
  if test -n "$1"
    then
      OPENSSL="$1/bin/openssl"
      export LD_LIBRARY_PATH="$1/lib:$1/lib64"
    else
      OPENSSL=openssl
    fi

  mkdir "CA/" 2>> "makecerts.log" 1>&2
  touch "CA/index.txt"
  echo -n "unique_subject = no" > "CA/index.txt.attr"
  $OPENSSL rand -hex 16 > "CA/serial"
  $OPENSSL rand -hex 16 > "tsa-serial"
  echo 1001 > "CA/crlnumber"
  date > "makecerts.log"
  "$OPENSSL" version 2>> "makecerts.log" 1>&2
  echo -n "$password" > "password.txt"

  printf "\nGenerate root CA certificate\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/CA.key \
      2>> "makecerts.log" 1>&2
  test_result $?
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" req -config "$CONF" -new -x509 -days 3600 -key CA/CA.key -out tmp/CACert.pem \
        -subj "/C=PL/O=osslsigncode/OU=Certification Authority/CN=Root CA" \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nGenerate intermediate CA certificate\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/intermediate.key \
        2>> "makecerts.log" 1>&2
    TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_intermediate.cnf"
    "$OPENSSL" req -config "$CONF" -new -key CA/intermediate.key -out CA/intermediate.csr \
        -subj "/C=PL/O=osslsigncode/OU=Certification Authority/CN=Intermediate CA" \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" ca -config "$CONF" -batch -in CA/intermediate.csr -out CA/intermediate.cer \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?
  "$OPENSSL" x509 -in CA/intermediate.cer -out tmp/intermediate.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate private RSA encrypted key\n" >> "makecerts.log"
  "$OPENSSL" genrsa -des3 -out CA/private.key -passout pass:"$password" \
      2>> "makecerts.log" 1>&2
  test_result $?
  cat CA/private.key >> tmp/keyp.pem 2>> "makecerts.log"
  test_result $?

  printf "\nGenerate private RSA decrypted key\n" >> "makecerts.log"
  "$OPENSSL" rsa -in CA/private.key -passin pass:"$password" -out tmp/key.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate a certificate to revoke\n" >> "makecerts.log"
  "$OPENSSL" req -config "$CONF" -new -key CA/private.key -passin pass:"$password" -out CA/revoked.csr \
      -subj "/C=PL/O=osslsigncode/OU=CSP/CN=Revoked/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" ca -config "$CONF" -batch -in CA/revoked.csr -out CA/revoked.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/revoked.cer -out tmp/revoked.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nRevoke above certificate\n" >> "makecerts.log"
  "$OPENSSL" ca -config "$CONF" -revoke CA/revoked.cer \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nAttach intermediate certificate to revoked certificate\n" >> "makecerts.log"
  cat tmp/intermediate.pem >> tmp/revoked.pem 2>> "makecerts.log"
  test_result $?

  printf "\nGenerate CRL file\n" >> "makecerts.log"
  TZ=GMT faketime -f '@2019-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_intermediate.cnf"
    "$OPENSSL" ca -config "$CONF" -gencrl -crldays 8766 -out tmp/CACertCRL.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nConvert revoked certificate to SPC format\n" >> "makecerts.log"
  "$OPENSSL" crl2pkcs7 -in tmp/CACertCRL.pem -certfile tmp/revoked.pem -outform DER -out tmp/revoked.spc \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate CSP Cross-Certificate\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/cross.key \
      2>> "makecerts.log" 1>&2
  TZ=GMT faketime -f '@2018-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_intermediate.cnf"
    "$OPENSSL" req -config "$CONF" -new -x509 -days 900 -key CA/cross.key -out tmp/crosscert.pem \
       -subj "/C=PL/O=osslsigncode/OU=CSP/CN=crosscert/emailAddress=osslsigncode@example.com" \
       2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nGenerate code signing certificate\n" >> "makecerts.log"
  "$OPENSSL" req -config "$CONF" -new -key CA/private.key -passin pass:"$password" -out CA/cert.csr \
      -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CSP/CN=Certificate/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" ca -config "$CONF" -batch -in CA/cert.csr -out CA/cert.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/cert.cer -out tmp/cert.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the key to DER format\n" >> "makecerts.log"
  "$OPENSSL" rsa -in tmp/key.pem -outform DER -out tmp/key.der -passout pass:"$password" \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the key to PVK format\n" >> "makecerts.log"
  "$OPENSSL" rsa -in tmp/key.pem -outform PVK -out tmp/key.pvk -pvk-none \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the certificate to DER format\n" >> "makecerts.log"
  "$OPENSSL" x509 -in tmp/cert.pem -outform DER -out tmp/cert.der \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nAttach intermediate certificate to code signing certificate\n" >> "makecerts.log"
  cat tmp/intermediate.pem >> tmp/cert.pem 2>> "makecerts.log"
  test_result $?

  printf "\nConvert the certificate to SPC format\n" >> "makecerts.log"
  "$OPENSSL" crl2pkcs7 -nocrl -certfile tmp/cert.pem -outform DER -out tmp/cert.spc \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the certificate and the key into a PKCS#12 container\n" >> "makecerts.log"
  "$OPENSSL" pkcs12 -export -in tmp/cert.pem -inkey tmp/key.pem -out tmp/cert.p12 -passout pass:"$password" \
      -keypbe aes-256-cbc -certpbe aes-256-cbc \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate expired certificate\n" >> "makecerts.log"
  "$OPENSSL" req -config "$CONF" -new -key CA/private.key -passin pass:"$password" -out CA/expired.csr \
      -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CSP/CN=Expired/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" ca -config "$CONF" -enddate "190101000000Z" -batch -in CA/expired.csr -out CA/expired.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/expired.cer -out tmp/expired.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nAttach intermediate certificate to expired certificate\n" >> "makecerts.log"
  cat tmp/intermediate.pem >> tmp/expired.pem 2>> "makecerts.log"
  test_result $?

  printf "\nGenerate Root CA TSA certificate\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/TSACA.key \
      2>> "makecerts.log" 1>&2
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_tsa_root.cnf"
    "$OPENSSL" req -config "$CONF" -new -x509 -days 3600 -key CA/TSACA.key -out tmp/TSACA.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nGenerate TSA certificate\n" >> "makecerts.log"
  CONF="${script_path}/openssl_tsa.cnf"
  "$OPENSSL" req -config "$CONF" -new -nodes -keyout tmp/TSA.key -out CA/TSA.csr \
      2>> "makecerts.log" 1>&2
  test_result $?
  CONF="${script_path}/openssl_tsa_root.cnf"
  "$OPENSSL" ca -config "$CONF" -batch -in CA/TSA.csr -out CA/TSA.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/TSA.cer -out tmp/TSA.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nSave the chain to be included in the TSA response\n" >> "makecerts.log"
  cat tmp/TSA.pem tmp/TSACA.pem > tmp/tsa-chain.pem 2>> "makecerts.log"

# copy new files
  if test -s tmp/intermediate.pem -a -s tmp/CACert.pem -a -s tmp/CACertCRL.pem \
      -a -s tmp/key.pem -a -s tmp/keyp.pem -a -s tmp/key.der -a -s tmp/key.pvk \
      -a -s tmp/cert.pem -a -s tmp/cert.p12 -a -s tmp/cert.der -a -s tmp/cert.spc \
      -a -s tmp/crosscert.pem -a -s tmp/expired.pem -a -s tmp/revoked.pem -a -s tmp/revoked.spc \
      -a -s tmp/TSA.pem -a -s tmp/TSA.key -a -s tmp/tsa-chain.pem
  then
    cp tmp/* ./
    printf "%s" "keys & certificates successfully generated"
  else
    printf "%s" "error logs ${result_path}/makecerts.log"
    result=1
  fi

# remove the working directory
  rm -rf "CA/"
  rm -rf "tmp/"

  exit "$result"
}

# Tests requirement
if test -n "$(command -v faketime)"
  then
    make_certs "$1"
    result=$?
  else
    printf "%s\n" "faketime not found in \$PATH"
    printf "%s\n" "tests skipped, please install faketime package"
    result=1
  fi

exit "$result"
