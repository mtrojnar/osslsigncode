#!/bin/bash

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

################################################################################
# OpenSSL settings
################################################################################

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
  $OPENSSL rand -hex 16 > "tmp/tsa-serial"
  echo 1001 > "CA/crlnumber"
  date > "makecerts.log"
  "$OPENSSL" version 2>> "makecerts.log" 1>&2
  echo -n "$password" > tmp/password.txt

################################################################################
# Root CA certificates
################################################################################

  printf "\nGenerate trusted root CA certificate\n" >> "makecerts.log"
 "$OPENSSL" genrsa -out CA/CAroot.key \
      2>> "makecerts.log" 1>&2
  test_result $?
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" req -config "$CONF" -new -x509 -days 7300 -key CA/CAroot.key -out tmp/CAroot.pem \
        -subj "/C=PL/O=osslsigncode/OU=Certification Authority/CN=Trusted Root CA" \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nPrepare the Certificate Signing Request (CSR)\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/CA.key \
      2>> "makecerts.log" 1>&2
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" req -config "$CONF" -new -key CA/CA.key -out CA/CACert.csr \
        -subj "/C=PL/O=osslsigncode/OU=Certification Authority/CN=Root CA" \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nGenerate Self-signed root CA certificate\n" >> "makecerts.log"
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" x509 -req -days 7300 -extfile "$CONF" -extensions ca_extensions \
        -signkey CA/CA.key \
        -in CA/CACert.csr -out tmp/CACert.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nGenerate Cross-signed root CA certificate\n" >> "makecerts.log"
  TZ=GMT faketime -f '@2018-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" x509 -req -days 7300 -extfile "$CONF" -extensions ca_extensions \
        -CA tmp/CAroot.pem -CAkey CA/CAroot.key -CAserial CA/CAroot.srl \
        -CAcreateserial -in CA/CACert.csr -out tmp/CAcross.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

################################################################################
# Private RSA keys
################################################################################

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

  printf "\nConvert the key to DER format\n" >> "makecerts.log"
  "$OPENSSL" rsa -in tmp/key.pem -outform DER -out tmp/key.der -passout pass:"$password" \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nConvert the key to PVK format\n" >> "makecerts.log"
  "$OPENSSL" rsa -in tmp/key.pem -outform PVK -out tmp/key.pvk -pvk-none \
      2>> "makecerts.log" 1>&2
  test_result $?

################################################################################
# Intermediate CA certificates
################################################################################

  CONF="${script_path}/openssl_intermediate.cnf"

  printf "\nGenerate intermediate CA certificate\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/intermediateCA.key \
        2>> "makecerts.log" 1>&2
    TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_intermediate.cnf"
    "$OPENSSL" req -config "$CONF" -new -key CA/intermediateCA.key -out CA/intermediateCA.csr \
        -subj "/C=PL/O=osslsigncode/OU=Certification Authority/CN=Intermediate CA" \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" ca -config "$CONF" -batch -in CA/intermediateCA.csr -out CA/intermediateCA.cer \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?
  "$OPENSSL" x509 -in CA/intermediateCA.cer -out tmp/intermediateCA.pem \
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
  cat tmp/intermediateCA.pem >> tmp/revoked.pem 2>> "makecerts.log"
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

  printf "\nConvert the certificate to DER format\n" >> "makecerts.log"
  "$OPENSSL" x509 -in tmp/cert.pem -outform DER -out tmp/cert.der \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nAttach intermediate certificate to code signing certificate\n" >> "makecerts.log"
  cat tmp/intermediateCA.pem >> tmp/cert.pem 2>> "makecerts.log"
  test_result $?

  printf "\nConvert the certificate to SPC format\n" >> "makecerts.log"
  "$OPENSSL" crl2pkcs7 -nocrl -certfile tmp/cert.pem -outform DER -out tmp/cert.spc \
      2>> "makecerts.log" 1>&2
  test_result $?

  ssl_version=$("$OPENSSL" version)
  if test "${ssl_version:8:1}" -eq 3
  then
    printf "\nConvert the certificate and the key into legacy PKCS#12 container with\
 RC2-40-CBC private key and certificate encryption algorithm\n" >> "makecerts.log"
    "$OPENSSL" pkcs12 -export -in tmp/cert.pem -inkey tmp/key.pem -out tmp/legacy.p12 -passout pass:"$password" \
        -keypbe rc2-40-cbc -certpbe rc2-40-cbc -legacy \
        2>> "makecerts.log" 1>&2
  else
    printf "\nConvert the certificate and the key into legacy PKCS#12 container with\
 RC2-40-CBC private key and certificate encryption algorithm\n" >> "makecerts.log"
    "$OPENSSL" pkcs12 -export -in tmp/cert.pem -inkey tmp/key.pem -out tmp/legacy.p12 -passout pass:"$password" \
        -keypbe rc2-40-cbc -certpbe rc2-40-cbc \
        2>> "makecerts.log" 1>&2
  fi
  test_result $?

  printf "\nConvert the certificate and the key into a PKCS#12 container with\
  AES-256-CBC private key and certificate encryption algorithm\n" >> "makecerts.log"
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
  cat tmp/intermediateCA.pem >> tmp/expired.pem 2>> "makecerts.log"
  test_result $?


################################################################################
# Intermediate CA certificates with CRL distribution point
################################################################################

  CONF="${script_path}/openssl_intermediate_crldp.cnf"

  printf "\nGenerate intermediate CA certificate with CRL distribution point\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/intermediateCA_crldp.key \
        2>> "makecerts.log" 1>&2
    TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_intermediate_crldp.cnf"
    "$OPENSSL" req -config "$CONF" -new -key CA/intermediateCA_crldp.key -out CA/intermediateCA_crldp.csr \
        -subj "/C=PL/O=osslsigncode/OU=Certification Authority/CN=Intermediate CA CRL DP" \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_root.cnf"
    "$OPENSSL" ca -config "$CONF" -batch -in CA/intermediateCA_crldp.csr -out CA/intermediateCA_crldp.cer \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?
  "$OPENSSL" x509 -in CA/intermediateCA_crldp.cer -out tmp/intermediateCA_crldp.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate a certificate with X509v3 CRL Distribution Points extension to revoke\n" >> "makecerts.log"
  "$OPENSSL" req -config "$CONF" -new -key CA/private.key -passin pass:"$password" -out CA/revoked_crldp.csr \
      -subj "/C=PL/O=osslsigncode/OU=CSP/CN=Revoked X509v3 CRL DP/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" ca -config "$CONF" -batch -in CA/revoked_crldp.csr -out CA/revoked_crldp.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/revoked_crldp.cer -out tmp/revoked_crldp.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nRevoke above certificate\n" >> "makecerts.log"
  "$OPENSSL" ca -config "$CONF" -revoke CA/revoked_crldp.cer \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nAttach intermediate certificate to revoked certificate\n" >> "makecerts.log"
  cat tmp/intermediateCA_crldp.pem >> tmp/revoked_crldp.pem 2>> "makecerts.log"
  test_result $?

  printf "\nGenerate CRL file\n" >> "makecerts.log"
  TZ=GMT faketime -f '@2019-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_intermediate_crldp.cnf"
    "$OPENSSL" ca -config "$CONF" -gencrl -crldays 8766 -out tmp/CACertCRL_crldp.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nConvert CRL file from PEM to DER (for CRL Distribution Points server to use) \n" >> "makecerts.log"
  "$OPENSSL" crl -in tmp/CACertCRL_crldp.pem -inform PEM -out tmp/CACertCRL.der -outform DER \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate code signing certificate with X509v3 CRL Distribution Points extension\n" >> "makecerts.log"
  "$OPENSSL" req -config "$CONF" -new -key CA/private.key -passin pass:"$password" -out CA/cert_crldp.csr \
      -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CSP/CN=Certificate X509v3 CRL DP/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" ca -config "$CONF" -batch -in CA/cert_crldp.csr -out CA/cert_crldp.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/cert_crldp.cer -out tmp/cert_crldp.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nAttach intermediate certificate to code signing certificate\n" >> "makecerts.log"
  cat tmp/intermediateCA_crldp.pem >> tmp/cert_crldp.pem 2>> "makecerts.log"
  test_result $?

################################################################################
# Time Stamp Authority certificates
################################################################################
  printf "\nGenerate Root CA TSA certificate\n" >> "makecerts.log"
  "$OPENSSL" genrsa -out CA/TSACA.key \
      2>> "makecerts.log" 1>&2
  TZ=GMT faketime -f '@2017-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_tsa_root.cnf"
    "$OPENSSL" req -config "$CONF" -new -x509 -days 7300 -key CA/TSACA.key -out tmp/TSACA.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nGenerate TSA certificate to revoke\n" >> "makecerts.log"
  CONF="${script_path}/openssl_tsa_root.cnf"
  "$OPENSSL" req -config "$CONF" -new -nodes -keyout tmp/TSA_revoked.key -out CA/TSA_revoked.csr \
      -subj "/C=PL/O=osslsigncode/OU=TSA/CN=Revoked/emailAddress=osslsigncode@example.com" \
      2>> "makecerts.log" 1>&2
  test_result $?
  CONF="${script_path}/openssl_tsa_root.cnf"
  "$OPENSSL" ca -config "$CONF" -batch -in CA/TSA_revoked.csr -out CA/TSA_revoked.cer \
      2>> "makecerts.log" 1>&2
  test_result $?
  "$OPENSSL" x509 -in CA/TSA_revoked.cer -out tmp/TSA_revoked.pem \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nRevoke above certificate\n" >> "makecerts.log"
  "$OPENSSL" ca -config "$CONF" -revoke CA/TSA_revoked.cer \
      2>> "makecerts.log" 1>&2
  test_result $?

  printf "\nGenerate TSA CRL file\n" >> "makecerts.log"
  TZ=GMT faketime -f '@2019-01-01 00:00:00' /bin/bash -c '
    script_path=$(pwd)
    OPENSSL="$0"
    export LD_LIBRARY_PATH="$1"
    CONF="${script_path}/openssl_tsa_root.cnf"
    "$OPENSSL" ca -config "$CONF" -gencrl -crldays 8766 -out tmp/TSACertCRL.pem \
        2>> "makecerts.log" 1>&2' "$OPENSSL" "$LD_LIBRARY_PATH"
  test_result $?

  printf "\nConvert TSA CRL file from PEM to DER (for CRL Distribution Points server to use)\n" >> "makecerts.log"
  "$OPENSSL" crl -in tmp/TSACertCRL.pem -inform PEM -out tmp/TSACertCRL.der -outform DER \
      2>> "makecerts.log" 1>&2
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

################################################################################
# Copy new files
################################################################################

  if test -s tmp/CACert.pem -a -s tmp/CAcross.pem -a -s tmp/CAroot.pem  \
      -a -s tmp/intermediateCA.pem -a -s tmp/intermediateCA_crldp.pem \
      -a -s tmp/CACertCRL.pem -a -s tmp/CACertCRL.der \
      -a -s tmp/TSACertCRL.pem -a -s tmp/TSACertCRL.der \
      -a -s tmp/key.pem -a -s tmp/keyp.pem -a -s tmp/key.der -a -s tmp/key.pvk \
      -a -s tmp/cert.pem -a -s tmp/cert.der -a -s tmp/cert.spc \
      -a -s tmp/cert.p12 -a -s tmp/legacy.p12 -a -s tmp/cert_crldp.pem\
      -a -s tmp/expired.pem \
      -a -s tmp/revoked.pem -a -s tmp/revoked_crldp.pem \
      -a -s tmp/TSA_revoked.pem \
      -a -s tmp/TSA.pem -a -s tmp/TSA.key -a -s tmp/tsa-chain.pem
  then
    mkdir -p "../certs"
    cp tmp/* ../certs
    printf "%s" "Keys & certificates successfully generated"
  else
    printf "%s" "Error logs ${result_path}/makecerts.log"
    result=1
  fi

################################################################################
# Remove the working directory
################################################################################

  rm -rf "CA/"
  rm -rf "tmp/"

  exit "$result"
}


################################################################################
# Tests requirement and make certs
################################################################################

if test -n "$(command -v faketime)"
  then
    make_certs "$1"
    result=$?
  else
    printf "%s" "faketime not found in \$PATH, please install faketime package"
    result=1
  fi

exit "$result"
