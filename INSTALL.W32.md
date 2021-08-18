# osslsigncode Windows install notes

### Building osslsigncode source with MSYS2 MinGW 64-bit and MSYS2 packages:

1) Download and install MSYS2 from https://msys2.github.io/ and follow installation instructions.
   Once up and running install even mingw-w64-x86_64-gcc, mingw-w64-x86_64-curl.
```
  pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-curl
```
   mingw-w64-x86_64-openssl and mingw-w64-x86_64-zlib packages are installed with dependencies.

2) Run "MSYS2 MinGW 64-bit" and build 64-bit Windows executables.
```
  cd osslsigncode-folder
  x86_64-w64-mingw32-gcc osslsigncode.c msi.c msi.h -o osslsigncode.exe \
    -lcrypto -lssl -lcurl \
    -D 'PACKAGE_STRING="osslsigncode 2.2"' \
    -D 'PACKAGE_BUGREPORT="Michal.Trojnara@stunnel.org"' \
    -D ENABLE_CURL
```

3) Run "Command prompt" and include "c:\msys64\mingw64\bin" folder as part of the path.
```
  path=%path%;c:\msys64\mingw64\bin
  cd osslsigncode-folder
  osslsigncode.exe -v
  osslsigncode 2.2, using:
        OpenSSL 1.1.1g  21 Apr 2020 (Library: OpenSSL 1.1.1g  21 Apr 2020)
        libcurl/7.70.0 OpenSSL/1.1.1g (Schannel) zlib/1.2.11 brotli/1.0.7 libidn2/2.3.0
        libpsl/0.21.0 (+libidn2/2.3.0) libssh2/1.9.0 nghttp2/1.40.0
```


### Building OpenSSL, Curl and osslsigncode sources with MSYS2 MinGW 64-bit:

1) Download and install MSYS2 from https://msys2.github.io/ and follow installation instructions.
   Once up and running install even: perl make autoconf automake libtool pkg-config.
```
  pacman -S perl make autoconf automake libtool pkg-config
```
   Make sure there are no curl, brotli, libpsl, libidn2 and nghttp2 packages installed:
```
  pacman -R mingw-w64-x86_64-curl \
    mingw-w64-x86_64-brotli \
    mingw-w64-x86_64-libpsl \
    mingw-w64-x86_64-libidn2 \
    mingw-w64-x86_64-nghttp2
```

   Run "MSYS2 MinGW 64-bit" in the administrator mode.

2) Build and install OpenSSL.
```
  cd openssl-(version)
  ./config --prefix='C:/OpenSSL' --openssldir='C:/OpenSSL'
  make && make install
```
 3) Build and install curl.
```
  cd curl-(version)
  ./buildconf
  ./configure --prefix='C:/curl' --with-ssl='C:/OpenSSL' \
    --disable-ftp --disable-tftp --disable-file --disable-dict \
    --disable-telnet --disable-imap --disable-smb --disable-smtp \
    --disable-gopher --disable-pop --disable-pop3 --disable-rtsp \
    --disable-ldap --disable-ldaps --disable-unix-sockets \
    --disable-pthreads --without-zstd
  make && make install
```

3) Build 64-bit Windows executables.
```
  cd osslsigncode-folder
  x86_64-w64-mingw32-gcc osslsigncode.c msi.c msi.h -o osslsigncode.exe \
    -L 'C:/OpenSSL/lib/' -lcrypto -lssl \
    -I 'C:/OpenSSL/include/' \
    -L 'C:/curl/lib' -lcurl \
    -I 'C:/curl/include' \
    -D 'PACKAGE_STRING="osslsigncode 2.2"' \
    -D 'PACKAGE_BUGREPORT="Michal.Trojnara@stunnel.org"' \
    -D ENABLE_CURL
```

4) Run "Command prompt" and copy required libraries.
```
  cd osslsigncode-folder
  copy C:\OpenSSL\bin\libssl-1_1-x64.dll
  copy C:\OpenSSL\bin\libcrypto-1_1-x64.dll
  copy C:\curl\bin\libcurl-4.dll
  copy C:\msys64\mingw64\bin\zlib1.dll

  osslsigncode.exe -v
  osslsigncode 2.2, using:
        OpenSSL 1.1.1k  25 Mar 2021 (Library: OpenSSL 1.1.1k  25 Mar 2021)
        libcurl/7.78.0 OpenSSL/1.1.1k zlib/1.2.11
```
