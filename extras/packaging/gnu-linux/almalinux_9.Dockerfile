FROM almalinux:9

WORKDIR /build

RUN mkdir -p /build/artifacts && \
    mkdir -p /root/rpmbuild/SOURCES && \
    dnf install -y epel-release && \
    dnf install -y almalinux-release-devel && \
    dnf install -y rpm-build rpmdevtools git gcc g++ make cmake wget \
    pkg-config dpkg-dev libtool autoconf automake systemd \
    python3-devel python3-setuptools python3-build \
    ncurses-devel readline-devel nettle-devel \
    gnutls-devel gmp-devel jsoncpp-devel libargon2-devel \
    openssl-devel fmt-devel asio-devel msgpack-devel yaml-cpp-devel \
    http-parser zlib-devel llhttp-devel \
    libupnp-devel libnatpmp-devel && \
    dnf --enablerepo=crb install -y cppunit-devel \
    libuv-devel libunistring-devel && \
    dnf --enablerepo=devel install -y gmp-static
    # dnf install -y p11-kit-devel

# RUN mkdir -p /build/gnutls && \
#     cd /build/gnutls && \
#     wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.4.tar.xz && \
#     tar xf gnutls-3.8.4.tar.xz && \
#     cd gnutls-3.8.4 && \
#     ./configure --with-included-libtasn1 --disable-libdane --enable-static && \
#     make install

COPY gnu-linux/almalinux /build/almalinux

ARG PKG_NAME
COPY rpm-${PKG_NAME}.tar.gz /root/rpmbuild/SOURCES/${PKG_NAME}.tar.gz

CMD cd /build/almalinux && \
    rpmbuild -ba dhtnet.spec && \
    cp /root/rpmbuild/SRPMS/*.rpm /build/artifacts/ && \
    cp /root/rpmbuild/RPMS/$(uname -m)/*.rpm /build/artifacts/
