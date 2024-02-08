# dsh - Distributed Shell

**dsh** is a Distributed Shell command-line program that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.

## Overview

**dsh** allows you to:

- Execute commands on remote peers in a DHT network.
- Establish connections with peers and execute binaries on their side.


### Options

**dsh** accepts the following command-line options:

- `-h, --help`: Show the help message and exit.
- `-v, --version`: Display the version of the program.
- `-l, --listen`: Launch the program in listen mode, waiting for incoming connections.
- `-b, --bootstrap [ADDRESS]`: Specify the address of the bootstrap node for DHT network initialization.
- `-s, --binary [PATH]`: Specify the binary to execute upon establishing a connection.
- `-p, --privateKey [PATH]`: Define the path to the private key.
- `-c, --certificate [PATH]`: Specify the path to the certificate.
- `-t, --turn_host [HOST]`: Define the TURN server host for NAT traversal.
- `-u, --turn_user [USERNAME]`: Specify the TURN server username for authentication.
- `-w, --turn_pass [PASSWORD]`: Define the TURN server password for authentication.
- `-r, --turn_realm [REALM]`: Specify the TURN server realm for additional security.
- `-d, --configuration [PATH]`: Define the path to the YAML configuration file for dsh.
- `-a, --anonymous_cnx`: Activate anonymous connection mode.

For example, to connect to a remote peer and specify a custom configuration in the YAML configuration file, you can use the following command:

```shell
dsh -d <configuration> <peer_identifier>
```