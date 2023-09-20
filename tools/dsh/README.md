# dsh - Distributed Shell

**dsh** is a Distributed Shell program that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.

## Overview

**dsh** allows you to:

- Execute commands on remote peers in a DHT network.
- Establish connections with peers and execute binaries on their side.


### Options

**dsh** accepts the following command-line options:

- `-h, --help`: Display help information for using **dsh**.
- `-V, --version`: Display the version information of **dsh**.
- `-l, --listen`: Run **dsh** in listen mode, allowing the program to accept incoming network connections and perform network-related tasks on request.
- `-b, --bootstrap <BOOTSTRAP_ADDRESS>`: Specify the address of a bootstrap node to connect to an existing DHT network. This option requires an argument. The default value is "bootstrap.jami.net" if not specified.
- `-s, --binary <BINARY_PATH>`: Specify the path to the binary that should be executed on the remote target when a connection is established. This option requires an argument. The default value is "bash" if not specified.
- `-I, --id_path <IDENTITY_PATH>`: Specify the path to the identity file, which contains information about the peer's identity and is used for DHT network interactions. This option requires an argument. The default value is "~/.dhtnet" if not specified.
- `<PEER_ID>`: The peer ID argument is required when not running in listen mode. It specifies the ID of the target peer or device in the DHT network with which the connection should be established.

For example, to connect to a remote peer and specify a custom bootstrap node, binary, and identity file, you can use the following command:

```shell
dsh -b <BOOTSTRAP_ADDRESS> -s <BINARY_PATH> -I <IDENTITY_PATH> <PEER_ID>
```