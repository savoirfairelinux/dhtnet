FROM ubuntu:24.10

WORKDIR /build

ENV EMAIL="contact@savoirfairelinux.com"
ENV DEBFULLNAME="Savoir-faire Linux"

RUN apt-get update && \
    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
    apt-get install -y \
        dialog apt-utils make devscripts build-essential debmake lintian \
    && apt-get clean && \
    mkdir -p /build/artifacts

RUN apt-get update && apt-get install -y \
        build-essential pkg-config cmake dpkg-dev gcc g++ git wget \
        libtool autotools-dev autoconf automake sbuild autopkgtest debhelper debhelper-compat \
        cython3 python3-dev python3-setuptools python3-build python3-virtualenv \
        libncurses5-dev libreadline-dev nettle-dev libcppunit-dev \
        libgnutls28-dev libuv1-dev libjsoncpp-dev libargon2-dev libunistring-dev \
        libssl-dev libfmt-dev libasio-dev libmsgpack-dev libyaml-cpp-dev \
        libupnp-dev libnatpmp-dev \
        systemd libzstd-dev\
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

ARG PKG_NAME
COPY deb-${PKG_NAME}.tar.gz /build/${PKG_NAME}.tar.gz

CMD tar -xzf ${PKG_NAME}.tar.gz && \
    cd ${PKG_NAME} && \
    debmake -b "dhtnet:bin" -y && \
    debuild && \
    cd .. && \
    rm -Rf ${PKG_NAME} ${PKG_NAME}.tar.gz && \
    cp /build/*.deb /build/artifacts/
