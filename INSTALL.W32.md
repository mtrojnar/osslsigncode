# osslsigncode Windows install notes

### Building osslsigncode source with MSYS2 MinGW 64-bit and MSYS2 packages:

1) Download and install MSYS2 from https://msys2.github.io/ and follow installation instructions.
   Once up and running install mingw-w64-x86_64-gcc and mingw-w64-x86_64-openssl packages.
```
  pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```
   mingw-w64-x86_64-zlib package is installed with dependencies.

2) Run "MSYS2 MinGW 64-bit" and build 64-bit Windows executables.
```
  cd osslsigncode-folder
  x86_64-w64-mingw32-gcc *.c -o osslsigncode.exe \
    -lcrypto -lssl -lws2_32 -lz \
    -D 'PACKAGE_STRING="osslsigncode x.y"' \
    -D 'PACKAGE_BUGREPORT="Your.Email@example.com"'
```

3) Run "Command prompt" and include "c:\msys64\mingw64\bin" folder as part of the path.
```
  path=%path%;c:\msys64\mingw64\bin
  cd osslsigncode-folder
  osslsigncode.exe -v
  osslsigncode 2.8, using:
        OpenSSL 3.2.0 23 Nov 2023 (Library: OpenSSL 3.2.0 23 Nov 2023)
  Default -CAfile location: /etc/ssl/certs/ca-certificates.crt
```


### Building OpenSSL and osslsigncode sources with MSYS2 MinGW 64-bit:

1) Download and install MSYS2 from https://msys2.github.io/ and follow installation instructions.
   Once up and running install even: perl make autoconf automake libtool pkg-config.
```
  pacman -S perl make autoconf automake libtool pkg-config
```
   Run "MSYS2 MinGW 64-bit" in the administrator mode.

2) Build and install OpenSSL.
```
  cd openssl-(version)
  ./config --prefix='C:/OpenSSL' --openssldir='C:/OpenSSL'
  make && make install

3) Build 64-bit Windows executables.
```
  cd osslsigncode-folder
  x86_64-w64-mingw32-gcc *.c -o osslsigncode.exe \
    -L "C:/OpenSSL/lib/" -lcrypto -lssl -lws2_32 -lz \
    -I "C:/OpenSSL/include/" \
    -D 'PACKAGE_STRING="osslsigncode x.y"' \
    -D 'PACKAGE_BUGREPORT="Your.Email@example.com"'
```

4) Run "Command prompt" and copy required libraries.
```
  cd osslsigncode-folder
  copy C:\OpenSSL\bin\libssl-1_1-x64.dll
  copy C:\OpenSSL\bin\libcrypto-1_1-x64.dll

  osslsigncode.exe -v
  osslsigncode 2.8, using:
        OpenSSL 3.2.0 23 Nov 2023 (Library: OpenSSL 3.2.0 23 Nov 2023)
  Default -CAfile location: /etc/ssl/certs/ca-certificates.crt
```

### Building OpenSSL and osslsigncode sources with Microsoft Visual Studio:

1) Install and integrate vcpkg: https://vcpkg.io/en/getting-started.html

2) Git clone osslsigncode: https://github.com/mtrojnar/osslsigncode/

3) Build osslsigncode with GUI or cmake.
  Navigate to the build directory and run CMake to configure the osslsigncode project
  and generate a native build system:
```
mkdir build && cd build && cmake -S .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=[installation directory] -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake
```
  Then call that build system to actually compile/link the osslsigncode project:
```
  cmake --build .
```

4) Make tests.
```
  ctest -C Release
```

5) Make install (with administrative privileges if necessary).
```
  cmake --install .
```
