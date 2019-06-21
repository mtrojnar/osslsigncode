#!/bin/sh

test_result() {
  if [ $1 -ne 0 ]
    then
      fail=$((fail + 1))
      result=1
      printf "Failed\n" >> "results.log"
    else
      count=$((count + 1))
    fi
}

result=0
count=0
fail=0
skip=0

result_path=$(pwd)
cd $(dirname "$0")
script_path=$(pwd)
result_path="${result_path}/logs"

rm -rf "${result_path}"
mkdir "${result_path}"
cd "${result_path}"

cp "../myapp.exe" "test.exe"
date > "results.log"

# 1. Signing a PE file
printf "\n1. Signing a PE file\n" >> "results.log"
../../osslsigncode sign -h sha256 \
    -certs "${script_path}/certs/cert.pem" -key "${script_path}/certs/key.pem" \
    -in "test.exe" -out "test1.exe" 2>> "results.log" 1>&2
test_result $?

# 2. Signing with a PEM key file with a password together with a PEM certificate
printf "\n2. Signing with a PEM key file with a password together with a PEM certificate\n" >> "results.log"
../../osslsigncode sign -h sha256 \
    -certs "${script_path}/certs/cert.pem" -key "${script_path}/certs/keyp.pem" -pass passme \
    -in "test.exe" -out "test2.exe" 2>> "results.log" 1>&2
test_result $?

# 3. Signing with a DER key file
printf "\n3. Signing with a DER key file\n" >> "results.log"
../../osslsigncode sign -h sha256 \
    -certs "${script_path}/certs/cert.pem" -key "${script_path}/certs/key.der" -pass passme \
    -in "test.exe" -out "test3.exe" 2>> "results.log" 1>&2
test_result $?

# 4. Signing with a PVK key file together with a SPC certificate
printf "\n4. Signing with a PVK key file together with a SPC certificate\n" >> "results.log"
../../osslsigncode sign -h sha256 \
    -certs "${script_path}/certs/cert.spc" -key "${script_path}/certs/key.pvk" -pass passme \
    -in "test.exe" -out "test4.exe" 2>> "results.log" 1>&2
test_result $?

# 5. Signing with a certificate and key stored in a PKCS#12 container
printf "\n5. Signing with a certificate and key stored in a PKCS#12 container\n" >> "results.log"
../../osslsigncode sign -h sha256 \
    -pkcs12 "${script_path}/certs/cert.p12" -pass passme \
    -in "test.exe" -out "test5.exe" 2>> "results.log" 1>&2
test_result $?

# 6. Signing a PE file with a timestamp
printf "\n6. Signing a PE file with a timestamp\n" >> "results.log"
../../osslsigncode sign -h sha256 \
    -certs "${script_path}/certs/cert.pem" -key "${script_path}/certs/key.pem" \
    -t http://time.certum.pl/ \
    -in "test.exe" -out "test6.exe" 2>> "results.log" 1>&2
test_result $?

# 7. Extracting the signature
cat "test6.exe" > "test7.exe"
printf "\n7. Extracting the signature\n" >> "results.log"
../../osslsigncode extract-signature -pem -in "test7.exe" -out "sign.pem" 2>> "results.log" 1>&2
test_result $?

# 8. Attaching the signature
printf "\n8. Attaching the signature\n" >> "results.log"
../../osslsigncode attach-signature -sigin "sign.pem" -in "test.exe" -out "test8.exe" 2>> "results.log" 1>&2
test_result $?

# 9. Removing the signature
cat "test8.exe" > "test9.exe"
printf "\n9. Removing the signature\n" >> "results.log"
../../osslsigncode remove-signature -in "test9.exe" -out "test10.exe" 2>> "results.log" 1>&2
test_result $?
if [ $result -eq 0 ]
  then
    # removed signature
    ../../osslsigncode verify -in "test10.exe" 2>> "verify1.log" 1>&2
    if ! grep -q "No signature found" "verify1.log"
    then
      fail=$((fail + 1))
      count=$((count - 1))
      result=1
    else
      cat "verify1.log" >> "results.log"
    fi
  fi

# 10. Verifying the signature
#printf "\n%s" "Number of the unique sha256sum: " >> "results.log"
#sha256sum test[0-9]*.exe | cut -d' ' -f1 | uniq | wc -l 2>> "results.log" 1>&2
#sha256sum test[0-9]*.exe 2>> "results.log" 1>&2

printf "\n10. Verifying the signature\n" >> "results.log"
    # signed PE file
../../osslsigncode verify -in "test1.exe" 2>> "verify2.log" 1>&2 && \
    # signed PE file with password
    ../../osslsigncode verify -in "test2.exe" 2>> "verify2.log" 1>&2 && \
    # signed PE file with DER key file
    ../../osslsigncode verify -in "test3.exe" 2>> "verify2.log" 1>&2 && \
    # signed PE file with PVK key & SPC certificate
    ../../osslsigncode verify -in "test4.exe" 2>> "verify2.log" 1>&2 && \
    # signed PE file with PKCS#12 container
    ../../osslsigncode verify -in "test5.exe" 2>> "verify2.log" 1>&2 && \
    # signed PE file with timestamp
    ../../osslsigncode verify -in "test6.exe" 2>> "verify2.log" 1>&2 && \
    # attached signature
    ../../osslsigncode verify -in "test8.exe" 2>> "verify2.log" 1>&2
test_result $?

if [ $result -eq 0 ] && [ $(grep "Calculated message digest" "verify2.log" | uniq | wc -l) -ne 1 ]
  then
    fail=$((fail + 1))
    count=$((count - 1))
    result=1
  elif [ $result -eq 0 ]
    then
      printf "Succeeded\n" >> "results.log"
  fi

# clean logs
if [ $result -eq 0 ]
  then
    rm -f test[0-9]*.exe
    rm -f verify[0-9]*.log
    rm -f test.exe
    rm -f sign.pem
  fi

#cat "../logs/results.log"
printf "%s\n" "./newtest.sh finished"
printf "%s\n" "summary: success $count, skip $skip, fail $fail"
exit $result
