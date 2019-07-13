#!/bin/sh
# requires mingw64-gcc, gcab, msitools, libgsf, libgsf-devel

result=0

result_path=$(pwd)
cd $(dirname "$0")
script_path=$(pwd)
result_path="${result_path}/logs"

rm -rf "${result_path}"
mkdir "${result_path}"
cd "${result_path}"

date > "results.log"
touch FoobarAppl10.exe
cp "../sample.wxs" "sample.wxs" 2>> "results.log" 1>&2

x86_64-w64-mingw32-gcc "../myapp.c" -o "test.exe" 2>> "results.log" 1>&2
gcab -c "test.ex_" "test.exe" 2>> "results.log" 1>&2
wixl -v "sample.wxs" 2>> "results.log" 1>&2

for plik in ${script_path}/recipes/*
  do
    /bin/sh $plik 3>&1 2>> "results.log" 1>&2
  done
count=$(grep -c "Test succeeded" "results.log")
if [ $count -ne 0 ]
  then
    skip=$(grep -c "Test skipped" "results.log")
    fail=$(grep -c "Test failed" "results.log")
    printf "%s\n" "./newtest.sh finished"
    printf "%s\n" "summary: success $count, skip $skip, fail $fail"
  else # no test was done
    result=1
  fi
rm -f "test.exe" "test.ex_" "sample.msi" "sample.wxs" "FoobarAppl10.exe"
rm -f "sign_pe.pem" "sign_msi.pem" "verify.log"
exit $result
