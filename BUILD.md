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

## Building with Docker

DHTNet includes a multi-stage Dockerfile that allows you to build the project in an isolated environment:

### Build targets

The Dockerfile has three targets:

- **`base`**: Sets up the build environment, installs dependencies, and configures CMake (including building dependency libraries like OpenDHT and PJPROJECT), but does not build dhtnet itself
- **`build`**: Compiles and installs the dhtnet library
- **`test`**: Runs tests and generates coverage reports

### Building the base image (dependencies only)

To build just the base image with all dependencies configured:

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

This will give you a shell inside the container where all dependencies are already configured. You can then manually run build commands, modify code, or test changes interactively.

## Contributing

If you encounter issues or want to contribute to DHTNet's development, please visit the [GitHub repository](https://github.com/savoirfairelinux/dhtnet) for more details on how to get involved.
