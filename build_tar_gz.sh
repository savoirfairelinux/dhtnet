#!/bin/bash
PKG_NAME=dhtnet
PKG_VERSION=0.2.0

FOLDER_NAME="${PKG_NAME}-${PKG_VERSION}"

rm -Rf "${FOLDER_NAME}"
rm -f "${PKG_NAME}-${PKG_VERSION}.tar.gz"
mkdir -p "${FOLDER_NAME}"

git submodule update --init --recursive

# copy source code
cp -Rf dependencies "${FOLDER_NAME}/dependencies"
cp -Rf include "${FOLDER_NAME}/include"
cp -Rf src "${FOLDER_NAME}/src"
cp -Rf tools "${FOLDER_NAME}/tools"
cp -Rf CMakeLists.txt "${FOLDER_NAME}/CMakeLists.txt"
cp -Rf COPYING "${FOLDER_NAME}/COPYING"
cp -Rf dhtnet.pc.in "${FOLDER_NAME}/dhtnet.pc.in"
cp -Rf README.md "${FOLDER_NAME}/README.md"

# copy debian conf
cp -Rf "extras/packaging/gnu-linux/debian" "${FOLDER_NAME}/debian"

tar -czf "${PKG_NAME}-${PKG_VERSION}.tar.gz" "${FOLDER_NAME}"

echo "Archive ${PKG_NAME}-${PKG_VERSION}.tar.gz is ready"
echo "Use   tar -xzf ${PKG_NAME}-${PKG_VERSION}.tar.gz   to unzip this file and package it with debuild"
