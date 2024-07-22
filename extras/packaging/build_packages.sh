#!/bin/bash
set -e

PKG_NAME=dhtnet
PKG_VERSION=0.2.0

FOLDER_NAME="${PKG_NAME}-${PKG_VERSION}"

# move pwd to the directory of this script (extras/packaging)
cd "$(dirname "$0")" || exit 1

rm -Rf "${FOLDER_NAME}"
rm -f "${PKG_NAME}-${PKG_VERSION}.tar.gz"
mkdir -p "${FOLDER_NAME}"

rm -Rf "../../dependencies/msgpack"
rm -Rf "../../dependencies/opendht"
rm -Rf "../../dependencies/pjproject"
rm -Rf "../../dependencies/restinio"
(cd ../.. && git submodule update --init --recursive)

# copy source code
cp -Rf ../../dependencies "${FOLDER_NAME}/dependencies"
cp -Rf ../../include "${FOLDER_NAME}/include"
cp -Rf ../../src "${FOLDER_NAME}/src"
cp -Rf ../../tools "${FOLDER_NAME}/tools"
cp -Rf ../../CMakeLists.txt "${FOLDER_NAME}/CMakeLists.txt"
cp -Rf ../../COPYING "${FOLDER_NAME}/COPYING"
cp -Rf ../../dhtnet.pc.in "${FOLDER_NAME}/dhtnet.pc.in"
cp -Rf ../../README.md "${FOLDER_NAME}/README.md"

# copy debian conf
cp -Rf "./gnu-linux/debian" "${FOLDER_NAME}/debian"

tar -czf "${PKG_NAME}-${PKG_VERSION}.tar.gz" "${FOLDER_NAME}"
rm -Rf "${FOLDER_NAME}"

echo "Archive ${PKG_NAME}-${PKG_VERSION}.tar.gz is ready, starting builds... (will take few minutes)"

#######################

# build deb package

docker build -t dhtnet-builder:ubuntu24 -f gnu-linux/ubuntu-24.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
docker run --rm -v "$(pwd)/ubuntu-24/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:ubuntu24

docker build -t dhtnet-builder:ubuntu22 -f gnu-linux/ubuntu-22.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
docker run --rm -v "$(pwd)/ubuntu-22/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:ubuntu22
