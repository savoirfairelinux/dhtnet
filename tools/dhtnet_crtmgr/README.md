# DHTNet Certificate Manager


## Description

The DHTNet Certificate Manager is a command-line tool designed to manage certificates for the DHTNet network. It provides functionality for generating and signing certificates.

## Features

- Generate new certificates
- Sign certificates
- Display the user identifier


## Installation

To install the DHTNet Certificate Manager, you must build the dhtnet library with the `DNC_SYSTEMD` and `BUILD_TOOLS` flags enabled. By default, these flags are turned on.

## Option
- `-h, --help`: Display this help message and then exit.
- `-v, --version`: Show the version of the program.
- `-p, --privatekey`: Provide the path to the private key as an argument.
- `-c, --certificate`: Provide the path to the certificate  as an argument.
- `-o, --output`: Provide the path where the generated certificate should be saved as an argument.
- `-g, --identifier`: Display the user identifier.
- `-n, --name`: Provide the name of the certificate to be generated.
- `-s, --setup`: Create an CA and an certificate.

## Usage

To create a new certficate:
```bash
dhtnet-crtmgr -o <output> -n <name>
```
Specify the path to save the generated certificate. The name is optional.

To create a certificate signed by another certificate:
```bash
dhtnet-crtmgr -o <output> -c <signer_certificate_path> -p <signer_private_key_path>
```

To display the identifier:
```bash
dhtnet-crtmgr -o <output> -c <certificate_path> -p <private_key_path>
```

To generate a CA and an certificate:
```bash
dhtnet-crtmgr -o <output> -s
```