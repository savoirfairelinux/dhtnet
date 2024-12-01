# Building DHTNet

This document provides instructions on how to build DHTNet from source code. Ensure that you have met all the dependencies before proceeding with the build.

## Dependencies

Follow these instructions to install DHTNet's dependencies depending on your system:

### Ubuntu 20.04+:

```bash
sudo apt install build-essential pkg-config cmake git wget \
                 libtool autotools-dev autoconf \
                 cython3 python3-dev python3-setuptools python3-build python3-virtualenv \
                 libncurses5-dev libreadline-dev nettle-dev libcppunit-dev \
                 libgnutls28-dev libuv1-dev libjsoncpp-dev libargon2-dev libunistring-dev \
                 libssl-dev libfmt-dev libhttp-parser-dev libasio-dev libmsgpack-dev libyaml-cpp-dev \
                 libnatpmp-dev libupnp-dev
```

### Fedora

```bash
sudo dnf install cmake gcc-c++ git readline-devel gnutls-devel msgpack-devel asio-devel libargon2-devel \
                 fmt-devel http-parser-devel cppunit-devel jsoncpp-devel libnatpmp-devel libupnp-devel \
                 libunistring-devel yaml-cpp-devel zlib-devel
```

### macOS

```bash
brew install gnutls msgpack-cxx argon2 asio
```

## Building Instructions

Follow these steps to build DHTNet (Note: You will need ressources (RAM, CPU) for the build to succeed):

### 1. Clone the DHTNet repository

Clone the DHTNet repository to your local machine:

```bash
git clone https://github.com/savoirfairelinux/dhtnet.git
cd dhtnet
```

### 2. Update dependencies

Run the following command:

```bash
git submodule update --init --recursive
```
This will ensure that you have the correct versions of the Git submodules required for the build process (OpenDHT, PJPROJECT, RESTinio).

### 3. Build

Create a build directory and use CMake to configure the build:

```bash
mkdir build
cd build
cmake ..
```

Or, if you want to override some variables, add them with -D :
```bash
cmake .. -DBUILD_DEPENDENCIES=On -DCMAKE_INSTALL_PREFIX=/usr
```

Finally, initiate the build process:

```bash
make -j
sudo make install
```

## Contributing

If you encounter issues or want to contribute to DHTNet's development, please visit the [GitHub repository](https://github.com/savoirfairelinux/dhtnet) for more details on how to get involved.
