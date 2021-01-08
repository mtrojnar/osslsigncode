#!/bin/sh
# mingw64-gcc, gcab, msitools, libgsf, libgsf-devel
# vim-common, libfaketime packages are required

result=0
count=0
skip=0
fail=0

result_path=$(pwd)
cd $(dirname "$0")
script_path=$(pwd)
result_path="${result_path}/logs"
certs_path="${script_path}/certs"

make_tests() {
  for plik in ${script_path}/recipes/*
    do
      /bin/sh $plik 3>&1 2>> "results.log" 1>&2
    done
    count=$(grep -c "Test succeeded" "results.log")
  if test $count -ne 0
    then
      skip=$(grep -c "Test skipped" "results.log")
      fail=$(grep -c "Test failed" "results.log")
      printf "%s\n" "testall.sh finished"
      printf "%s\n" "summary: success $count, skip $skip, fail $fail"
    else # no test was done
      result=1
    fi
}

rm -rf "${result_path}"
mkdir "${result_path}"
cd "${result_path}"
mkdir "notsigned" "sha256sum"

date > "results.log"
../../osslsigncode -v >> "results.log" 2>/dev/null

cd ${certs_path}
if test -s CACert.pem -a -s crosscert.pem -a -s expired.pem -a -s cert.pem \
    -a -s CACertCRL.pem -a -s revoked.pem -a -s key.pem -a -s keyp.pem \
    -a -s key.der -a -s cert.der -a -s cert.spc -a -s cert.p12
  then
    printf "%s\n" "keys & certificates path: ${certs_path}"
  else
    ./makecerts.sh $1
    result=$?
  fi
cd "${result_path}"

if test "$result" -ne 0
  then
    exit $result
  fi

# PE files support
if test -n "$(command -v x86_64-w64-mingw32-gcc)"
  then
    x86_64-w64-mingw32-gcc "../sources/myapp.c" -o "notsigned/test.exe" 2>> "results.log" 1>&2
  else
    printf "%s\n" "x86_64-w64-mingw32-gcc not found in \$PATH"
    printf "%s\n" "tests for PE files skipped, please install mingw64-gcc package"
  fi

# CAB files support
if test -n "$(command -v gcab)"
  then
    gcab -c "notsigned/test.ex_" "../sources/a" "../sources/b" "../sources/c" 2>> "results.log" 1>&2
  else
    printf "%s\n" "gcab not found in \$PATH"
    printf "%s\n" "tests for CAB files skipped, please install gcab package"
  fi

# MSI files support
if grep -q "no libgsf available" "results.log"
  then
    printf "%s\n" "signing MSI files requires libgsf/libgsf-devel packages and reconfiguration osslsigncode"
  else
    if test -n "$(command -v wixl)"
      then
        touch FoobarAppl10.exe
        cp "../sources/sample.wxs" "notsigned/sample.wxs" 2>> "results.log" 1>&2
        wixl -v "notsigned/sample.wxs" 2>> "results.log" 1>&2
        rm -f "notsigned/sample.wxs"
        rm -f "FoobarAppl10.exe"
      else
        printf "%s\n" "wixl not found in \$PATH"
        printf "%s\n" "tests for MSI files skipped, please install msitools package"
      fi
  fi

# CAT files support
if test -s "../sources/good.cat"
  then
    cp "../sources/good.cat" "notsigned/good.cat"
  fi

# TXT files support
if test -s "../sources/utf8.ps1"
  then
    cp "../sources/utf8.ps1" "notsigned/utf8.ps1"
  fi
if test -s "../sources/utf8bom.ps1"
  then
    cp "../sources/utf8bom.ps1" "notsigned/utf8bom.ps1"
  fi
if test -s "../sources/utf16le.ps1"
  then
    cp "../sources/utf16le.ps1" "notsigned/utf16le.ps1"
  fi

# Timestamping support
if grep -q "no libcurl available" "results.log"
  then
    printf "%s\n" "configure --with-curl is required for timestamping support"
  fi

# Tests requirements
if test -n "$(command -v faketime)"
  then
    if test -n "$(command -v xxd)"
      then
        make_tests
        result=$?
        rm -r -f "notsigned/" "sha256sum/"
        rm -f sign_[1-9].pem sign_[1-9].der
        rm -f "verify.log"
      else
        printf "%s\n" "xxd not found in \$PATH"
        printf "%s\n" "tests skipped, please install vim-common package"
      fi
  else
    printf "%s\n" "faketime not found in \$PATH"
    printf "%s\n" "tests skipped, please install faketime package"
  fi

exit $result
