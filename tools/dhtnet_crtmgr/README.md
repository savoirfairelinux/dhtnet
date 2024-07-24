# DHTNet Certificate Manager


## Description

The DHTNet Certificate Manager is a command-line tool designed to manage certificates and keys for the DHTNet network. It provides functionality for generating and signing certificates.

## Features

- Generate new certificates
- Sign certificates
- Display the user identifier


## Option
- `-h, --help`: Display this help message and then exit.
- `-v, --version`: Show the version of the program.
- `-p, --privatekey [FILE]`: Provide the path to the private key as an argument.
- `-c, --certificate [FILE]`: Provide the path to the certificate  as an argument.
- `-o, --output [FOLDER]`: Provide the path where the generated certificate should be saved as an argument.
- `-a, --identifier`: Display the user identifier.
- `-n, --name [NAME]`: Provide the name of the certificate to be generated.
- `-s, --setup`: Create an CA and an certificate.
- `-i, --interactive`: Create certificate using interactive mode.

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
dhtnet-crtmgr -a -c <certificate_path> -p <private_key_path>
```

To generate a CA and an certificate:
```bash
dhtnet-crtmgr -o <output> -s
```

Generating certificate using user-friendly interface:
```bash
dhtnet-crtmgr --interactive
```
