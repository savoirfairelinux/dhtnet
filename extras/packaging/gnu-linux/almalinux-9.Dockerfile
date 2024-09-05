FROM almalinux:9

WORKDIR /build

RUN mkdir -p /build/artifacts && \
    mkdir -p /root/rpmbuild/SOURCES && \
    dnf install -y epel-release && \
    dnf install -y rpm-build rpmdevtools git gcc g++ make cmake wget \
    pkg-config dpkg-dev libtool autoconf automake systemd \
    python3-devel python3-setuptools python3-build \
    # python3-virtualenv
    ncurses-devel readline-devel nettle-devel \
    # cppunit-devel
    gnutls-devel libuv jsoncpp-devel libargon2-devel libunistring \
    # libuv-devel libunistring-devel
    openssl-devel fmt-devel asio-devel msgpack-devel yaml-cpp-devel \
    http-parser zlib-devel llhttp-devel \
    # http-parser-devel
    libupnp-devel libnatpmp-devel

COPY gnu-linux/almalinux /build/almalinux

ARG PKG_NAME
COPY rpm-${PKG_NAME}.tar.gz /root/rpmbuild/SOURCES/${PKG_NAME}.tar.gz

CMD cd /build/almalinux && \
    rpmbuild -ba dhtnet.spec && \
    cp /root/rpmbuild/SRPMS/*.rpm /build/artifacts/ && \
    cp /root/rpmbuild/RPMS/x86_64/*.rpm /build/artifacts/
