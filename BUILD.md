# Building DHTNet

This document provides instructions on how to build DHTNet from source code. Ensure that you have met all the dependencies before proceeding with the build.

## Dependencies

Follow these instructions to install DHTNet's dependencies depending on your system:

### Ubuntu 24.04+:

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

CMake 3.28 or newer is required.

## Building Instructions

Follow these steps to build DHTNet (Note: You will need ressources (RAM, CPU) for the build to succeed):

### 1. Clone the DHTNet repository

Clone the DHTNet repository to your local machine:

```bash
git clone https://github.com/savoirfairelinux/dhtnet.git
cd dhtnet
```

### 2. Build

Configure and build DHTNet with its bundled dependencies:

```bash
cmake -S . -B build
cmake --build build --parallel
```

The bundled CMake dependencies are added directly to the build with
`FetchContent`. Their normal build-system dependency tracking prevents
unchanged targets from rebuilding. PJProject uses a content-keyed bootstrap
only when no system `libpjproject` package is available. CMake downloads each
dependency at its pinned revision during the first configure.

To use dependencies installed by the system instead:

```bash
cmake -S . -B build \
    -DBUILD_DEPENDENCIES=Off \
    -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build --parallel
```

Install the completed build with `cmake --install build`.

## Building with Docker

DHTNet includes a multi-stage Dockerfile that allows you to build the project in an isolated environment:

### Build targets

The Dockerfile has three targets:

- **`base`**: Sets up the build environment and source tree
- **`build`**: Compiles and installs the dhtnet library
- **`test`**: Runs tests and generates coverage reports

### Building the development environment

To build an image with the toolchain and source tree ready to configure:

```bash
docker build --target base -t dhtnet:base .
```

### Building the full image

To build the complete image with dhtnet compiled:

```bash
docker build --target build -t dhtnet:latest .
```

### Developing inside the Docker environment

To enter the Docker container for interactive development, you can use the base image:

```bash
docker run -it dhtnet:base /bin/bash
```

This gives you a shell with the required system packages and source tree. You can
then configure and build DHTNet with the commands above.

## Contributing

If you encounter issues or want to contribute to DHTNet's development, please visit the [GitHub repository](https://github.com/savoirfairelinux/dhtnet) for more details on how to get involved.
