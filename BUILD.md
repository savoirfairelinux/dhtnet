# Building DHTNet

This document provides instructions on how to build DHTNet from source code. Ensure that you have met all the dependencies before proceeding with the build.

## Dependencies

DHTNet depends on the following libraries:

- **OpenDHT** 2.6, used to launch DHT nodes.
- **[pjproject](https://github.com/savoirfairelinux/pjproject)**, used for ICE negotiation.
- **msgpack-c** 1.2+, used for data serialization.
- **GnuTLS** 3.3+, used for cryptographic operations.
- **Nettle** 2.4+, a GnuTLS dependency for crypto.
- **{fmt}** 9.0+, for log formatting.

## Building Instructions

Follow these steps to build DHTNet:

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

Create a build directory and use CMake to configure the build:

```bash
cd dependencies && ./build.py && cd ..
mkdir build
cd build
cmake ..
```
Finally, initiate the build process:

```bash
make
```

## Contributing

If you encounter issues or wish to contribute to DHTNet's development, please visit the [GitHub repository](https://github.com/savoirfairelinux/dhtnet) for more details on how to get involved.