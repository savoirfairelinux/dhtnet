FROM ubuntu:24.04 AS test-u24
WORKDIR /tests
COPY ubuntu-24/dhtnet*.tar.gz /tests/
RUN apt install -y /tests/dhtnet*.tar.gz
RUN dnc --version && \
    dhtnet-crtmgr --version && \
    dhtnet-crtmgr --setup -o /etc/dhtnet/ && \
    export SERVER_DHT_ID=$(dhtnet-crtmgr -a -c /etc/dhtnet/id/id-server.crt -p /etc/dhtnet/id/id-server.pem) && \
    export SERVER_DHT_ID="${SERVER_DHT_ID#Public key id: }" && \
    mkdir -p /root/.dnc && \
    dhtnet-crtmgr -o /root/.dnc -c /etc/dhtnet/CA/ca-server.crt -p /etc/dhtnet/CA/ca-server.pem -n id-client && \
    ls -l /root/.dnc

