FROM fedora:40

WORKDIR /build

RUN dnf install -y fedora-packager fedora-review git gcc g++ make cmake

COPY gnu-linux/fedora /build/fedora

ARG PKG_NAME
COPY rpm-${PKG_NAME}.tar.gz /build/fedora/${PKG_NAME}.tar.gz

CMD cd /build/fedora && \
    fedpkg --release f40 mockbuild && \
    defpkg --release f40 lint
