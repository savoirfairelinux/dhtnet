# dsh - Distributed Shell

**dsh** is a Distributed Shell command-line program that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.

## Overview

**dsh** allows you to:

- Establish connections with peers and execute binaries on their side. Default binary: **bash**


### Options

**dsh** accepts the following command-line options:

- `-h, --help`: Show the help message and exit.
- `-v, --version`: Display the version of the program.
- `-l, --listen`: Launch the program in listen mode, waiting for incoming connections.
- `-b, --bootstrap [ADDRESS]`: Specify the address of the bootstrap node for DHT network initialization.
- `-s, --binary [COMMAND]`: Specify the binary to execute upon establishing a connection.
- `-p, --privateKey [FILE]`: Define the path to the private key.
- `-c, --certificate [FILE]`: Specify the path to the certificate.
- `-t, --turn_host [HOST]`: Define the TURN server host for NAT traversal.
- `-u, --turn_user [USER]`: Specify the TURN server username for authentication.
- `-w, --turn_pass [SECRET]`: Define the TURN server password for authentication.
- `-r, --turn_realm [REALM]`: Specify the TURN server realm for additional security.
- `-d, --configuration [FILE]`: Define the path to the YAML configuration file for dsh.
- `-a, --anonymous`: Activate anonymous connection mode.

For example, to connect to a remote peer and specify a custom configuration in the YAML configuration file, you can use the following command:

```shell
dsh -d <configuration> <peer_identifier>
```