#!/bin/sh
# Run inside the digest-pinned Alpine container, without any GitHub tokens.
set -eu

apk add --update --no-cache \
    build-base cmake binutils file python3 py3-cryptography openssl \
    openssl-dev openssl-libs-static zlib-dev zlib-static linux-headers

python3 -c 'import cryptography; print(cryptography.__version__)'
mkdir -p /work/source
cp -R /source/. /work/source/
cd /work/source

# Historical tags predate OSSLSIGNCODE_STATIC_PIE. Backport just the linker
# choice; never let their trailing -pie override the driver's -static-pie.
python3 - <<'PY'
from pathlib import Path
path = Path('cmake/SetCompilerFlags.cmake')
source = path.read_text()
if 'OSSLSIGNCODE_STATIC_PIE' not in source:
    old = 'PRIVATE -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack'
    if source.count(old) != 1:
        raise SystemExit('Cannot safely backport static PIE to this tag')
    path.write_text(source.replace(old, old.replace('-fPIE -pie', '-fPIE -static-pie')))
PY

cmake -G 'Unix Makefiles' -S . -B /work/build \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX=/work/dist \
    -DZLIB_USE_STATIC_LIBS=TRUE \
    -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DOSSLSIGNCODE_STATIC_PIE=ON \
    -DCMAKE_EXE_LINKER_FLAGS=-s
cmake --build /work/build --parallel 2

bin=/work/build/osslsigncode
file "$bin"
# A static executable alone is not sufficient: require PIE for ASLR, no
# interpreter or shared libraries, RELRO, and a non-executable stack.
readelf -h "$bin" | grep -Eq 'Type:[[:space:]]+DYN[[:space:]]'
if readelf -lW "$bin" | grep -q INTERP || readelf -dW "$bin" | grep -q '(NEEDED)'; then
    echo '::error::binary depends on a dynamic loader or shared libraries'
    exit 1
fi
readelf -lW "$bin" | grep -q GNU_RELRO
readelf -lW "$bin" | awk '$1 == "GNU_STACK" && $7 == "RW" { found = 1 } END { exit !found }'

ctest --test-dir /work/build --output-on-failure -C "$BUILD_TYPE"

cd /work
asset="osslsigncode-${VERSION}-linux-${ARCH}"
install -Dm755 "$bin" "stage/${asset}/osslsigncode"
cp source/COPYING.txt source/LICENSE.txt "stage/${asset}/"
tar -C stage -czf "${asset}.tar.gz" "${asset}"
sha256sum "${asset}.tar.gz"
