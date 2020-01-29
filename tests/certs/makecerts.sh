#!/bin/sh

result=0

test_result() {
  if [ "$1" == 0 ]
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
  CONF="${script_path}/openssltest.cnf"
  TEMP_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
  if test -n "$1"
    then
      OPENSSL="$1/bin/openssl"
      LD_LIBRARY_PATH="$1/lib"
    else
      OPENSSL=openssl
    fi

  mkdir "demoCA/" 2>> "makecerts.log" 1>&2
  touch "demoCA/index.txt"
  touch "demoCA/index.txt.attr"
  echo 1000 > "demoCA/serial"
  date > "makecerts.log"
  $OPENSSL version 2>> "makecerts.log" 1>&2
  echo -n "$password" > "password.txt"

  printf "\nGenerate root CA certificate\n" >> "makecerts.log"
  $OPENSSL genrsa -out demoCA/CA.key \
      2>> "makecerts.log" 1>&2
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL=openssl
    CONF="${script_path}/openssltest.cnf"
    $OPENSSL req -config $CONF -new -x509 -days 1800 -key demoCA/CA.key -out tmp/CACert.pem \
        -subj "/C=PL/O=osslsigncode/OU=Root CA/CN=CA/emailAddress=CA@example.com" \
        2>> "makecerts.log" 1>&2'
  test_result $?

  printf "\nGenerate private RSA encrypted key\n" >> "makecerts.log"
  $OPENSSL genrsa -des3 -out demoCA/private.key -passout pass:$password \
      2>> "makecerts.log" 1>&2
  test_result $?
  cat demoCA/private.key >> tmp/keyp.pem 2>> "makecerts.log"

  printf "\nGenerate private RSA decrypted key\n" >> "makecerts.log"
  $OPENSSL rsa -in demoCA/private.key -passin pass:$password -out tmp/key.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate a certificate to revoke\n" >> "makecerts.log"
  $OPENSSL req -config $CONF -new -key demoCA/private.key -passin pass:$password -out demoCA/revoked.csr \
      -subj "/C=PL/O=osslsigncode/OU=CA/CN=revoked/emailAddress=revoked@example.com" \
      2>> "makecerts.log" 1>&2
  $OPENSSL ca -config $CONF -batch -in demoCA/revoked.csr -out demoCA/revoked.cer \
      2>> "makecerts.log" 1>&2
  $OPENSSL x509 -in demoCA/revoked.cer -out tmp/revoked.pem \
      2>> "makecerts.log" 1>&2

  printf "\nRevoke above certificate\n" >> "makecerts.log"
  $OPENSSL ca -config $CONF -revoke demoCA/1000.pem \
      2>> "makecerts.log" 1>&2

  printf "\nGenerate CRL file\n" >> "makecerts.log"
  TZ=GMT faketime -f '@2019-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL=openssl
    CONF="${script_path}/openssltest.cnf"
    $OPENSSL ca -config $CONF -gencrl -crldays 8766 -out tmp/CACertCRL.pem \
        2>> "makecerts.log" 1>&2'

  printf "\nGenerate CSP Cross-Certificate\n" >> "makecerts.log"
  $OPENSSL genrsa -out demoCA/cross.key \
      2>> "makecerts.log" 1>&2
  TZ=GMT faketime -f '@2018-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL=openssl
   CONF="${script_path}/openssltest.cnf"
   $OPENSSL req -config $CONF -new -x509 -days 900 -key demoCA/cross.key -out tmp/crosscert.pem \
       -subj "/C=PL/O=osslsigncode/OU=CSP/CN=crosscert/emailAddress=CA@example.com" \
       2>> "makecerts.log" 1>&2'
  test_result $?

  printf "\nGenerate code signing certificate\n" >> "makecerts.log"
  $OPENSSL req -config $CONF -new -key demoCA/private.key -passin pass:$password -out demoCA/cert.csr \
      -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CA/CN=localhost/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  $OPENSSL ca -config $CONF -batch -in demoCA/cert.csr -out demoCA/cert.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  $OPENSSL x509 -in demoCA/cert.cer -out tmp/cert.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the key to DER format\n" >> "makecerts.log"
  $OPENSSL rsa -in tmp/key.pem -outform DER -out tmp/key.der -passout pass:$password \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the certificate to DER format\n" >> "makecerts.log"
  $OPENSSL x509 -in tmp/cert.pem -outform DER -out tmp/cert.der \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the certificate to SPC format\n" >> "makecerts.log"
  $OPENSSL crl2pkcs7 -nocrl -certfile tmp/cert.pem -outform DER -out tmp/cert.spc \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the certificate and the key into a PKCS#12 container\n" >> "makecerts.log"
  $OPENSSL pkcs12 -export -in tmp/cert.pem -inkey tmp/key.pem -out tmp/cert.p12 -passout pass:$password \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate expired certificate\n" >> "makecerts.log"
  $OPENSSL req -config $CONF -new -key demoCA/private.key -passin pass:$password -out demoCA/expired.csr \
      -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CA/CN=expired/emailAddress=expired@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  $OPENSSL ca -config $CONF -enddate "190101000000Z" -batch -in demoCA/expired.csr -out demoCA/expired.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  $OPENSSL x509 -in demoCA/expired.cer -out tmp/expired.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

# copy new files
  if [ -s tmp/CACert.pem ] && [ -s tmp/crosscert.pem ] && [ -s tmp/expired.pem ] && [ -s tmp/cert.pem ] && \
    [ -s tmp/CACertCRL.pem ] && [ -s tmp/revoked.pem ] && [ -s tmp/key.pem ] && [ -s tmp/keyp.pem ] && \
    [ -s tmp/key.der ] && [ -s tmp/cert.der ] && [ -s tmp/cert.spc ] && [ -s tmp/cert.p12 ]
  then
    cp tmp/* ./
    printf "%s\n" "keys & certificates successfully generated"
    printf "%s\n" "makecerts.sh finished"
    rm -f "makecerts.log"
  else
    printf "%s\n" "makecerts.sh failed"
    printf "%s\n" "error logs ${result_path}/makecerts.log"
    result=1
  fi

# remove the working directory
  rm -rf "demoCA/"
  rm -rf "tmp/"

# restore settings
  LD_LIBRARY_PATH=$TEMP_LD_LIBRARY_PATH

  exit $result
}

# Tests requirement
if [ -n "$(command -v faketime)" ]
  then
    make_certs $1
    result=$?
  else
    printf "%s\n" "faketime not found in \$PATH"
    printf "%s\n" "tests skipped, please install faketime package"
    result=1
  fi

exit $result
