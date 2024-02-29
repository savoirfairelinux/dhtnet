# Building DHTNet

This document provides instructions on how to build DHTNet from source code. Ensure that you have met all the dependencies before proceeding with the build.

## Dependencies
Follow these instructions to install DHTNet dependencies depending on your system:

### Debian/Ubuntu

#### Ubuntu 20.04+:

```bash
sudo apt install libncurses5-dev libreadline-dev nettle-dev libgnutls28-dev libargon2-dev libmsgpack-dev libssl-dev libfmt-dev libjsoncpp-dev libhttp-parser-dev libasio-dev libyaml-cpp-dev libunistring-dev libcppunit-dev
```

### Fedora
```bash
sudo dnf install readline-devel gnutls-devel msgpack-devel asio-devel libargon2-devel fmt-devel http-parser-devel cppunit-devel jsoncpp-devel
```

### macOS
```bash
brew install gnutls msgpack-cxx argon2 asio
```

## Building Instructions

Follow these steps to build DHTNet ( Note: You will need ressources (RAM, CPU) for the build to succeed ):

### 1. Clone the DHTNet Repository

Clone the DHTNet repository to your local machine:

```bash
git clone https://github.com/savoirfairelinux/dhtnet.git
cd dhtnet
```

### 2. Update dependencies:

Ensure that you have the latest versions of the required Git submodules, pjproject, and OpenDHT. Run the following command:

   ```bash
   git submodule update --init --recursive
   ```
This step ensures that your project has the most up-to-date dependencies for the build process.

### 3. Install dependencies:

#### Add tools and libraries

##### Ubuntu 20.04+:

```bash
sudo apt install build-essential pkg-config cmake git wget libtool autotools-dev autoconf cython3 python3-dev python3-setuptools pyt>
```

### 4. Build:

Create a build directory and use CMake to configure the build:

```bash
mkdir build
cd build
cmake .. [-DBUILD_DEPENDENCIES=On] [-DCMAKE_INSTALL_PREFIX=/usr]
```
Finally, initiate the build process:

```bash
make -j
sudo make install
```

## Contributing

If you encounter issues or wish to contribute to DHTNet's development, please visit the [GitHub repository](https://github.com/savoirfairelinux/dhtnet) for more details on how to get involved.
