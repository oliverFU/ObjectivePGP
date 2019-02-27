#!/usr/bin/env bash

BASE_PWD="$PWD"
SCRIPT_DIR="$(dirname "$0")"

BORINGSSL_SRC_DIR="${SCRIPT_DIR}/../vendor/boringssl-src"
BORINGSSL_BUILD_DIR="${SCRIPT_DIR}/../vendor/boringssl-build"
LIBS_DIR="${SCRIPT_DIR}/../vendor/libs"

rm -rf "${BORINGSSL_SRC_DIR}"
rm -rf "${BORINGSSL_BUILD_DIR}"

curl -Lk https://github.com/google/boringssl/archive/chromium-stable.zip -o vendor/boringssl-chromium-stable.zip
unzip -q vendor/boringssl-chromium-stable.zip -d vendor/
rm -f vendor/boringssl-chromium-stable.zip
mv vendor/boringssl-chromium-stable "${BORINGSSL_SRC_DIR}"

cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT=macosx          -DCMAKE_OSX_DEPLOYMENT_TARGET="10.10" -DCMAKE_OSX_ARCHITECTURES=x86_64 -H"${BORINGSSL_SRC_DIR}" -B"${BORINGSSL_BUILD_DIR}/macosx"
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT=iphoneos        -DCMAKE_OSX_DEPLOYMENT_TARGET="7.0" -DCMAKE_OSX_ARCHITECTURES=arm64 -H"${BORINGSSL_SRC_DIR}" -B"${BORINGSSL_BUILD_DIR}/iphoneos_arm64"
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT=iphoneos        -DCMAKE_OSX_DEPLOYMENT_TARGET="7.0" -DCMAKE_OSX_ARCHITECTURES=armv7 -H"${BORINGSSL_SRC_DIR}" -B"${BORINGSSL_BUILD_DIR}/iphoneos_armv7"
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT=iphoneos        -DCMAKE_OSX_DEPLOYMENT_TARGET="7.0" -DCMAKE_OSX_ARCHITECTURES=armv7s -H"${BORINGSSL_SRC_DIR}" -B"${BORINGSSL_BUILD_DIR}/iphoneos_armv7s"
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_DEPLOYMENT_TARGET="7.0" -DCMAKE_OSX_ARCHITECTURES=i386 -H"${BORINGSSL_SRC_DIR}" -B"${BORINGSSL_BUILD_DIR}/iphonesimulator_i386"
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_DEPLOYMENT_TARGET="7.0" -DCMAKE_OSX_ARCHITECTURES=x86_64 -H"${BORINGSSL_SRC_DIR}" -B"${BORINGSSL_BUILD_DIR}/iphonesimulator_x86_64"
make -j 8 --quiet -C "${BORINGSSL_BUILD_DIR}/macosx" crypto
make -j 8 --quiet -C "${BORINGSSL_BUILD_DIR}/iphoneos_arm64" crypto
make -j 8 --quiet -C "${BORINGSSL_BUILD_DIR}/iphoneos_armv7" crypto
make -j 8 --quiet -C "${BORINGSSL_BUILD_DIR}/iphoneos_armv7s" crypto
make -j 8 --quiet -C "${BORINGSSL_BUILD_DIR}/iphonesimulator_i386" crypto
make -j 8 --quiet -C "${BORINGSSL_BUILD_DIR}/iphonesimulator_x86_64" crypto

lipo -create \
     "${BORINGSSL_BUILD_DIR}/macosx/crypto/libcrypto.a" \
     -o "${LIBS_DIR}/macosx/libcrypto.a"

lipo -create \
     "${BORINGSSL_BUILD_DIR}/iphoneos_arm64/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphoneos_armv7/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphoneos_armv7s/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphonesimulator_i386/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphonesimulator_x86_64/crypto/libcrypto.a" \
     -o "${LIBS_DIR}/ios/libcrypto.a"

rm -rf "${LIBS_DIR}/ios/include/"
cp -R "${BORINGSSL_SRC_DIR}/include/" "${LIBS_DIR}/ios/"
rm -rf "${LIBS_DIR}/macosx/include/"
cp -R "${BORINGSSL_SRC_DIR}/include/" "${LIBS_DIR}/macosx/"

rm -rf "${BORINGSSL_SRC_DIR}"
rm -rf "${BORINGSSL_BUILD_DIR}"

# Update list of exported symbols
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols
xcrun nm -gUj "${LIBS_DIR}/macosx/libcrypto.a" | grep -v "^$" | grep "^_" > "${LIBS_DIR}/macosx/symbols"
xcrun nm -gUj "${LIBS_DIR}/ios/libcrypto.a" | grep -v "^$" | grep "^_" > "${LIBS_DIR}/ios/symbols"

rm -rf "${BORINGSSL_SRC_DIR}"
rm -rf "${BORINGSSL_BUILD_DIR}"
