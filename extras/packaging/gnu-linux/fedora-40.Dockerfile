FROM fedora:40

WORKDIR /build

RUN mkdir -p /build/artifacts && \
    dnf install -y fedora-packager fedora-review git gcc g++ make cmake wget \
    pkg-config dpkg-dev libtool autoconf automake systemd \
    python3-devel python3-setuptools python3-build python3-virtualenv \
    ncurses-devel readline-devel nettle-devel cppunit-devel \
    gnutls-devel libuv-devel jsoncpp-devel libargon2-devel libunistring-devel \
    openssl-devel fmt-devel asio-devel msgpack-devel yaml-cpp-devel \
    http-parser-devel zlib-devel llhttp-devel \
    libupnp-devel libnatpmp-devel 

COPY gnu-linux/fedora /build/fedora

ARG PKG_NAME
COPY rpm-${PKG_NAME}.tar.gz /build/fedora/${PKG_NAME}.tar.gz

CMD cd /build/fedora && \
    fedpkg --release f40 local && \
    (fedpkg --release f40 lint || true) && \
    cp /build/fedora/*.rpm /build/artifacts/ && \
    cp /build/fedora/x86_64/*.rpm /build/artifacts/
