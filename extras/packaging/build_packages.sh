#!/bin/bash
set -e

PKG_NAME=dhtnet
PKG_VERSION=0.2.0

FOLDER_NAME="${PKG_NAME}-${PKG_VERSION}"

# move pwd to the directory of this script (extras/packaging)
cd "$(dirname "$0")" || exit 1

rm -Rf "${FOLDER_NAME}"
rm -f -- *${PKG_NAME}-${PKG_VERSION}.tar.gz
mkdir -p "${FOLDER_NAME}"

rm -Rf "../../dependencies/msgpack"
rm -Rf "../../dependencies/opendht"
rm -Rf "../../dependencies/pjproject"
rm -Rf "../../dependencies/restinio"
(cd ../.. && git submodule update --init --recursive)

build_ubuntu=false
build_ubuntu20=false
build_ubuntu22=false
build_ubuntu24=false
build_debian=false
build_debian10=false
build_debian11=false
build_debian12=false

parse_args() {
    while [ "$1" != "" ]; do
        case $1 in
            -u | --ubuntu )         build_ubuntu=true
                                    build_ubuntu20=true
                                    build_ubuntu22=true
                                    build_ubuntu24=true
                                    ;;
            -u20 | --ubuntu20 )     build_ubuntu20=true
                                    build_ubuntu=true
                                    ;;
            -u22 | --ubuntu22 )     build_ubuntu22=true
                                    build_ubuntu=true
                                    ;;
            -u24 | --ubuntu24 )     build_ubuntu24=true
                                    build_ubuntu=true
                                    ;;
            -d | --debian )         build_debian=true
                                    build_debian10=true
                                    build_debian11=true
                                    build_debian12=true
                                    ;;
            -d10 | --debian10 )     build_debian10=true
                                    build_debian=true
                                    ;;
            -d11 | --debian11 )     build_debian11=true
                                    build_debian=true
                                    ;;
            -d12 | --debian12 )     build_debian12=true
                                    build_debian=true
                                    ;;
            -a | --all )            build_ubuntu=true
                                    # not working: build_ubuntu20=true
                                    build_ubuntu22=true
                                    build_ubuntu24=true
                                    build_debian=true
                                    # not working: build_debian10=true
                                    # not working: build_debian11=true
                                    build_debian12=true
                                    ;;
            * )                     echo "Argument '$1' is not recognized"
                                    ;;
        esac
        shift
    done
}

parse_args "$@"


# copy source code
cp -Rf ../../dependencies "${FOLDER_NAME}/dependencies"
cp -Rf ../../include "${FOLDER_NAME}/include"
cp -Rf ../../src "${FOLDER_NAME}/src"
cp -Rf ../../tools "${FOLDER_NAME}/tools"
cp -Rf ../../CMakeLists.txt "${FOLDER_NAME}/CMakeLists.txt"
cp -Rf ../../COPYING "${FOLDER_NAME}/COPYING"
cp -Rf ../../dhtnet.pc.in "${FOLDER_NAME}/dhtnet.pc.in"
cp -Rf ../../README.md "${FOLDER_NAME}/README.md"

if [ "$build_ubuntu" == true ] || [ "$build_debian" == true ]; then
    # copy debian conf
    cp -Rf "./gnu-linux/debian" "${FOLDER_NAME}/debian"

    tar -czf "deb-${PKG_NAME}-${PKG_VERSION}.tar.gz" "${FOLDER_NAME}"
    rm -Rf "${FOLDER_NAME}/debian"
fi

rm -Rf "${FOLDER_NAME}"
echo "Archives <os>-${PKG_NAME}-${PKG_VERSION}.tar.gz are ready, starting builds... (will take few minutes)"

#######################

# build Ubuntu package (deb-*)
if [ "$build_ubuntu24" == true ]; then
    mkdir -p ubuntu-24
    docker build -t dhtnet-builder:ubuntu24 -f gnu-linux/ubuntu-24.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
    docker run --rm -v "$(pwd)/ubuntu-24/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:ubuntu24
    rm -f ubuntu-24/build-at-*
    echo "Ubuntu 24.04 package built at $(date)" > "ubuntu-24/build-at-$(date +%F-%R)"
fi

if [ "$build_ubuntu22" == true ]; then
    mkdir -p ubuntu-22
    docker build -t dhtnet-builder:ubuntu22 -f gnu-linux/ubuntu-22.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
    docker run --rm -v "$(pwd)/ubuntu-22/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:ubuntu22
    rm -f ubuntu-22/build-at-*
    echo "Ubuntu 22.04 package built at $(date)" > "ubuntu-22/build-at-$(date +%F-%R)"
fi

if [ "$build_ubuntu20" == true ]; then
    mkdir -p ubuntu-20
    docker build -t dhtnet-builder:ubuntu20 -f gnu-linux/ubuntu-20.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
    docker run --rm -v "$(pwd)/ubuntu-20/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:ubuntu20
    rm -f ubuntu-20/build-at-*
    echo "Ubuntu 20.04 package built at $(date)" > "ubuntu-20/build-at-$(date +%F-%R)"
fi

# build Debian package (deb-*)
if [ "$build_debian12" == true ]; then
    mkdir -p debian-12
    docker build -t dhtnet-builder:debian12 -f gnu-linux/debian-12.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
    docker run --rm -v "$(pwd)/debian-12/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:debian12
    rm -f debian-12/build-at-*
    echo "Debian 12 package built at $(date)" > "debian-12/build-at-$(date +%F-%R)"
fi

if [ "$build_debian11" == true ]; then
    mkdir -p debian-11
    docker build -t dhtnet-builder:debian11 -f gnu-linux/debian-11.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
    docker run --rm -v "$(pwd)/debian-11/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:debian11
    rm -f debian-11/build-at-*
    echo "Debian 11 package built at $(date)" > "debian-11/build-at-$(date +%F-%R)"
fi

if [ "$build_debian10" == true ]; then
    mkdir -p debian-10
    docker build -t dhtnet-builder:debian10 -f gnu-linux/debian-10.Dockerfile --build-arg PKG_NAME="$FOLDER_NAME" .
    docker run --rm -v "$(pwd)/debian-10/":/build/debs -e PKG_NAME="$FOLDER_NAME" dhtnet-builder:debian10
    rm -f debian-10/build-at-*
    echo "Debian 10 package built at $(date)" > "debian-10/build-at-$(date +%F-%R)"
fi
