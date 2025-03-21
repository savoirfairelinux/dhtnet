
# Getting Started using dhtnet package

The `dhtnet` package includes binaries for multiple tools developed using the dhtnet library, along with automation scripts designed to simplify the creation of your own `dnc server` and `dnc client`.

Below, we provide instructions on how to use the `dnc tool` included in the dhtnet package. For more detailed information about the functionality of `dnc`, please refer to [dnc documentation](dnc/README.md) .

## Prerequisites
You can download latest and/or stable builds from https://dhtnet.sfl.io.  
To install .deb, you can use `apt install dhtnet-xxx.deb`, and .rpm can be installed using `dnf install dhtnet_xxx.rpm`.  
On fedora, you may require to install EPEL using `dnf install epel-release`.  
On Redhat / Almalinux, EPEL may also be required, look at each distribution to find the installation command.  

## Setup instructions for dnc server:
1. Create a server config and keys using `dhtnet-crtmgr --interactive` (run as root or with sudo is required).
2. Choose **server** and then use default configuration, or tweak values if you prefer.
3. If you want to review or edit configuration (to enable verbose mode for exemple), open `/etc/dhtnet/dnc.yaml`.
4. When ready, turn your server ON using `systemctl start dnc`. You can verify status using `systemctl status dnc`.

Your **server ID** (needed for clients to connect at you) is printed during the `dhtnet-crtmgr` setup, and is printed at start of logs when starting server with `systemctl start dnc`.
If needed, you can get it anytime using `dhtnet-crtmgr -a -c /etc/dhtnet/id/id-server.crt -p /etc/dhtnet/id/id-server.pem`.


## Setup instructions for dnc client:

1. Create a client configuration and keys using `dhtnet-crtmgr --interactive` (preferably run as your user).
2. Select **client** for the first prompt (default).
3. When prompted to use the server CA to sign the client keys, choose based on your setup:
    - If the server and client are on the same host, you can answer **yes**.
    - If you are setting up only the client, answer **no**.
    - If the server is on a different host and you want to enforce security, answer **no** and update the keys later (see `anonymous` section below).
4. Proceed with the default configuration or adjust values as needed.
5. To review or modify the configuration (e.g., to enable verbose mode), open `$HOME/.dnc/config.yml`.

To connect, you can use `dnc -d $HOME/.dnc/config.yml <server ID>`.  
If you answered **yes** at question about setting up ssh for you, then you can use `ssh <user>@dnc/<server ID>` to reach SSH on server using dnc layer.  

For exemple:
```sh
ssh mypeer@dnc/2f4975e7b11a0908bd400b27130fe9a496d0f415
```


## Security Settings

### `anonymous` setting
By default, the server allows connections from any client. To modify this behavior, adjust the `anonymous` setting in the server configuration.

The `anonymous` setting is a boolean value that controls access permissions:
- **`true`** (default): Allows open access to all clients (recommended for public servers).
- **`false`**: Restricts access to only authorized clients (recommended for secure environments).

#### Configuring Client Access for `anonymous: false`
When `anonymous` is set to `false`, clients must authenticate using a key signed by the server’s CA certificate. Follow these steps to generate and configure the client key:

1. Retrieve the server's CA certificate:
   ```bash
   cd /etc/dhtnet/CA/
   cp ca-server.crt ca-server.pem ~/client-certificates/
   ```
2. Generate a client key in `$HOME/.dnc/` using the server’s certificate:
   ```bash
   dhtnet-crtmgr -o `$HOME/.dnc/` -c ~/client-certificates/ca-server.crt -p ~/client-certificates/ca-server.pem
   ```
3. If the certificate and key are stored in a different location than `$HOME/.dnc/`, update `$HOME/.dnc/config.yml` accordingly:
   ```yaml
   certificate: MYPATH/certificate.crt  
   privateKey: MYPATH/certificate.pem
   ```
---

### `authorized_services` setting
Another critical security setting is `authorized_services`, which is configured on the server and defines the `ip` and `port` that the client can access.

When the dnc client establishes a connection to a remote dnc server, it attempts to reach `ip:port` **from that remote server**. 

To allow access to an HTTP server running on the server host, for example:

- Allow `127.0.0.1:80` on the server in the configuration file `$HOME/.dnc/config.yml`.
- On the client, specify the corresponding port using:
  ```bash
  --port 80
  ```

This ensures that only authorized services can be accessed through the connection.

## Restarting the Server
After making any changes to the security settings, restart the server to apply the updates:
```bash
systemctl restart dnc
```