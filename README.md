osslsigncode
============

## BUILD STATUS

[![CI](https://github.com/mtrojnar/osslsigncode/actions/workflows/ci.yml/badge.svg)](https://github.com/mtrojnar/osslsigncode/actions/workflows/ci.yml)

## WHAT IS IT?

osslsigncode is a small tool that implements part of the functionality
of the Microsoft tool signtool.exe - more exactly the Authenticode
signing and timestamping. But osslsigncode is based on OpenSSL and cURL,
and thus should be able to compile on most platforms where these exist.

## WHY?

Why not use signtool.exe? Because I don't want to go to a Windows
machine every time I need to sign a binary - I can compile and build
the binaries using Wine on my Linux machine, but I can't sign them
since the signtool.exe makes good use of the CryptoAPI in Windows, and
these APIs aren't (yet?) fully implemented in Wine, so the signtool.exe
tool  would fail. And, so, osslsigncode was born.

## WHAT CAN IT DO?

It can sign and timestamp PE (EXE/SYS/DLL/etc), CAB, CAT and MSI files.
It supports the equivalent of signtool.exe's "-j javasign.dll -jp low",
i.e. add a valid signature for a CAB file containing Java files.
It supports getting the timestamp through a proxy as well. It also
supports signature verification, removal and extraction.

## BUILDING

This section covers building osslsigncode for [Unix-like](https://en.wikipedia.org/wiki/Unix-like) operating systems.
See [INSTALL.W32.md](https://github.com/mtrojnar/osslsigncode/blob/master/INSTALL.W32.md) for Windows notes.
We highly recommend downloading a [release tarball](https://github.com/mtrojnar/osslsigncode/releases) instead of cloning from a git repository.

### Configure, build, make tests and install osslsigncode

* Install prerequisites on a Debian-based distributions, such as Ubuntu:
```
  sudo apt update && sudo apt install cmake libssl-dev libcurl4-openssl-dev zlib1g-dev python3
```
* Install prerequisites on macOS with Homebrew:
```
  brew install cmake pkg-config openssl@1.1
  export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig"
```
**NOTE:** osslsigncode requires CMake 3.17 or newer.

You may need to use `cmake3` instead of `cmake` to complete the following steps on your system.
* Navigate to the build directory and run CMake to configure the osslsigncode project
  and generate a native build system:
```
  mkdir build && cd build && cmake -S ..
```
  optional CMake parameters:
```
  -DCMAKE_BUILD_TYPE=Debug
  -DCMAKE_C_COMPILER=clang
  -DCMAKE_PREFIX_PATH=[openssl directory];[curl directory]
  -DCMAKE_INSTALL_PREFIX=[installation directory]
  -DBASH_COMPLETION_USER_DIR=[bash completion installation directory]

```
* Then call that build system to actually compile/link the osslsigncode project (alias `make`):
```
  cmake --build .
```
* Make test:
```
  ctest -C Release
```
* Make install:
```
  sudo cmake --install .
```
* Make tarball (simulate autotools' `make dist`):
```
  cmake --build . --target package_source
```

## USAGE

Before you can sign a file you need a Software Publishing
Certificate (spc) and a corresponding private key.

This article provides a good starting point as to how
to do the signing with the Microsoft signtool.exe:

  http://www.matthew-jones.com/articles/codesigning.html

To sign with osslsigncode you need the certificate file mentioned in the
article above, in SPC or PEM format, and you will also need the private
key which must be a key file in DER or PEM format, or if osslsigncode was
compiled against OpenSSL 1.0.0 or later, in PVK format.

To sign a PE or MSI file you can now do:
```
  osslsigncode sign -certs <cert-file> -key <der-key-file> \
    -n "Your Application" -i http://www.yourwebsite.com/ \
    -in yourapp.exe -out yourapp-signed.exe
```
or if you are using a PEM or PVK key file with a password together
with a PEM certificate:
```
  osslsigncode sign -certs <cert-file> \
    -key <key-file> -pass <key-password> \
    -n "Your Application" -i http://www.yourwebsite.com/ \
    -in yourapp.exe -out yourapp-signed.exe
```
or if you want to add a timestamp as well:
```
  osslsigncode sign -certs <cert-file> -key <key-file> \
    -n "Your Application" -i http://www.yourwebsite.com/ \
    -t http://timestamp.digicert.com \
    -in yourapp.exe -out yourapp-signed.exe
```
You can use a certificate and key stored in a PKCS#12 container:
```
  osslsigncode sign -pkcs12 <pkcs12-file> -pass <pkcs12-password> \
    -n "Your Application" -i http://www.yourwebsite.com/ \
    -in yourapp.exe -out yourapp-signed.exe
```
To sign a CAB file containing java class files:
```
  osslsigncode sign -certs <cert-file> -key <key-file> \
    -n "Your Application" -i http://www.yourwebsite.com/ \
    -jp low \
    -in yourapp.cab -out yourapp-signed.cab
```
Only the 'low' parameter is currently supported.

If you want to use PKCS11 token, you should indicate PKCS11 engine and module.
An example of using osslsigncode with SoftHSM:
```
  osslsigncode sign \
    -pkcs11engine /usr/lib64/engines-1.1/pkcs11.so \
    -pkcs11module /usr/lib64/pkcs11/libsofthsm2.so \
    -pkcs11cert 'pkcs11:token=softhsm-token;object=cert' \
    -key 'pkcs11:token=softhsm-token;object=key' \
    -in yourapp.exe -out yourapp-signed.exe
```

You can check that the signed file is correct by right-clicking
on it in Windows and choose Properties --> Digital Signatures,
and then choose the signature from the list, and click on
Details. You should then be presented with a dialog that says
amongst other things that "This digital signature is OK".

## UNAUTHENTICATED BLOBS

The "-addUnauthenticatedBlob" parameter adds a 1024-byte unauthenticated blob
of data to the signature in the same area as the timestamp.  This can be used
while signing, while timestamping, after a file has been code signed, or by
itself.  This technique (but not this project) is used by Dropbox, GoToMeeting,
and Summit Route.

### Example 1. Sign and add blob to unsigned file

```shell
osslsigncode sign -addUnauthenticatedBlob -pkcs12 yourcert.pfx -pass your_password -n "Your Company" -i https://YourSite.com/ -in srepp.msi -out srepp_added.msi
```

### Example 2. Timestamp and add blob to signed file

```shell
osslsigncode.exe add -addUnauthenticatedBlob -t http://timestamp.digicert.com -in your_signed_file.exe -out out.exe
```

### Example 3. Add blob to signed and time-stamped file

```shell
osslsigncode.exe add -addUnauthenticatedBlob -in your_signed_file.exe -out out.exe
```

### WARNING

This feature allows for doing dumb things.  Be very careful with what you put
in the unauthenticated blob, as an attacker could modify this.  Do NOT, under
any circumstances, put a URL here that you will use to download an additional
file.  If you do do that, you would need to check the newly downloaded file is
code signed AND that it has been signed with your cert AND that it is the
version you expect.

## BUGS, QUESTIONS etc.

Check whether your your question or suspected bug was already
discussed on https://github.com/mtrojnar/osslsigncode/issues.
Otherwise, open a new issue.

BUT, if you have questions related to generating spc files,
converting between different formats and so on, *please*
spend a few minutes searching on google for your particular
problem since many people probably already have had your
problem and solved it as well.
