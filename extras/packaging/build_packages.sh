#!/bin/bash
set -e

# move pwd to the directory of this script (extras/packaging)
cd "$(dirname "$0")" || exit 1

PKG_NAME=dhtnet
PKG_VERSION="$(head -1 build.version | grep -o '^[0-9\.]\+$' -)"

FOLDER_NAME="${PKG_NAME}-${PKG_VERSION}"


rm -Rf "${FOLDER_NAME}"
rm -f -- *${PKG_NAME}-${PKG_VERSION}.tar.gz
mkdir -p "${FOLDER_NAME}"

rm -Rf "../../dependencies/msgpack"
rm -Rf "../../dependencies/opendht"
rm -Rf "../../dependencies/pjproject"
rm -Rf "../../dependencies/restinio"
(cd ../.. && git submodule update --init --recursive)

build_ubuntu=false
build_ubuntu20_04=false
build_ubuntu22_04=false
build_ubuntu24_04=false
build_debian=false
build_debian10=false
build_debian11=false
build_debian12=false
build_fedora=false
build_fedora39=false
build_fedora40=false
build_almalinux=false
build_almalinux9=false

parse_args() {
    while [ "$1" != "" ]; do
        case $1 in
            -u | --ubuntu )                     build_ubuntu=true
                                                build_ubuntu20_04=true
                                                build_ubuntu22_04=true
                                                build_ubuntu24_04=true
                                                ;;
            -u20 | -u20.04 | --ubuntu20.04 )    build_ubuntu20_04=true
                                                build_ubuntu=true
                                                ;;
            -u22 | -u22.04 | --ubuntu22.04 )    build_ubuntu22_04=true
                                                build_ubuntu=true
                                                ;;
            -u24 | -u24.04 | --ubuntu24.04 )    build_ubuntu24_04=true
                                                build_ubuntu=true
                                                ;;
            -d | --debian )                     build_debian=true
                                                build_debian10=true
                                                build_debian11=true
                                                build_debian12=true
                                                ;;
            -d10 | --debian10 )                 build_debian10=true
                                                build_debian=true
                                                ;;
            -d11 | --debian11 )                 build_debian11=true
                                                build_debian=true
                                                ;;
            -d12 | --debian12 )                 build_debian12=true
                                                build_debian=true
                                                ;;
            -f | --fedora )                     build_fedora=true
                                                build_fedora39=true
                                                build_fedora40=true
                                                ;;
            -f40 | --fedora40 )                 build_fedora40=true
                                                build_fedora=true
                                                ;;
            -f39 | --fedora39 )                 build_fedora39=true
                                                build_fedora=true
                                                ;;
            -al | --almalinux )                 build_almalinux=true
                                                build_almalinux9=true
                                                ;;
            -al9 | --almalinux9 )               build_almalinux=true
                                                build_almalinux9=true
                                                ;;
            -a | --all )                        build_ubuntu=true
                                                # not working: build_ubuntu20=true
                                                build_ubuntu22_04=true
                                                build_ubuntu24_04=true
                                                build_debian=true
                                                # not working: build_debian10=true
                                                # not working: build_debian11=true
                                                build_debian12=true
                                                build_fedora=true
                                                build_fedora39=true
                                                build_fedora40=true
                                                build_almalinux=true
                                                build_almalinux9=true
                                                ;;
            * )                                 echo "Argument '$1' is not recognized"
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

if [ "$build_fedora" == true ] || [ "$build_almalinux" == true ]; then
    # copy fedora conf
    #cp -Rf "./gnu-linux/fedora" "${FOLDER_NAME}/fedora"

    tar -czf "rpm-${PKG_NAME}-${PKG_VERSION}.tar.gz" "${FOLDER_NAME}"
    #rm -Rf "${FOLDER_NAME}/fedora"
fi

rm -Rf "${FOLDER_NAME}"
echo "Archives <os>-${PKG_NAME}-${PKG_VERSION}.tar.gz are ready, starting builds... (will take few minutes)"

#######################

started_builds=()
started_pid=()
remainning_builds=0

build_target() {
    target="$1"
    mkdir -p "$target"
    docker build -t "dhtnet-builder:$target" -f "gnu-linux/$target.Dockerfile" --build-arg PKG_NAME="$FOLDER_NAME" .
    remainning_builds=$((remainning_builds+1))
    (
        docker run --rm \
            -v "$(pwd)/$target/":/build/artifacts \
            -e PKG_NAME="$FOLDER_NAME" "dhtnet-builder:$target" > "$target/build.log" 2>&1;
        if [ $? -eq 0 ]; then
            rm -f -- $target/build-at-*
            echo "$target package built at $(date)" > "$target/build-at-$(date +%F-%R)"
            echo "Successfully built $target package"
        else
            echo "Failed to build $target package, check log for more details"
        fi
    ) &
    started_pid+=("$!")
    started_builds+=("$target")
}

# build Ubuntu package (deb-*)
if [ "$build_ubuntu24_04" == true ]; then
    build_target "ubuntu_24.04"
fi

if [ "$build_ubuntu22_04" == true ]; then
    build_target "ubuntu_22.04"
fi

if [ "$build_ubuntu20_04" == true ]; then
    build_target "ubuntu_20.04"
fi

# build Debian package (deb-*)
if [ "$build_debian12" == true ]; then
    build_target "debian_12"
fi

if [ "$build_debian11" == true ]; then
    build_target "debian_11"
fi

if [ "$build_debian10" == true ]; then
    build_target "debian_10"
fi

# build Fedora package (rpm-*)
if [ "$build_fedora40" == true ]; then
    build_target "fedora_40"
fi

if [ "$build_fedora39" == true ]; then
    build_target "fedora_39"
fi

if [ "$build_almalinux9" == true ]; then
    build_target "almalinux_9"
fi


while [ $remainning_builds -gt 0 ]; do
    time="$(date +%T)"
    for index in "${!started_builds[@]}"; do
        if [ "${started_pid[$index]}" != "" ]; then
            if ps -p "${started_pid[$index]}" > /dev/null; then
                echo "[$time] Still building ${started_builds[$index]}... (pid: ${started_pid[$index]})"
            else
                echo "[$time] Build ${started_builds[$index]} finished"
                remainning_builds=$((remainning_builds-1))
                started_pid[index]=""
            fi
        fi
    done
    if [ $remainning_builds -gt 0 ]; then
        sleep 30
    fi
done

echo "[$(date +%T)] All builds finished:"
for target in "${started_builds[@]}"; do
    echo "  - $target"
done
