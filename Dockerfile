FROM ubuntu:24.04 AS base

RUN apt-get update && apt-get install -y \
    dialog apt-utils \
    && apt-get clean \
    && echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt-get update && apt-get install -y \
    build-essential pkg-config cmake git wget \
    libtool autotools-dev autoconf \
    cython3 python3-dev python3-setuptools python3-build python3-virtualenv \
    libncurses5-dev libreadline-dev nettle-dev libcppunit-dev \
    libgnutls28-dev libuv1-dev libjsoncpp-dev libargon2-dev libunistring-dev \
    libssl-dev libfmt-dev libasio-dev libmsgpack-cxx-dev libyaml-cpp-dev \
    libupnp-dev libnatpmp-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

WORKDIR /dhtnet

COPY . .

FROM base AS build

RUN cmake -S . -B build_dev \
    -DBUILD_DEPENDENCIES=On \
    -DCMAKE_INSTALL_PREFIX=/usr

RUN cmake --build build_dev --parallel $(nproc) \
    && cmake --install build_dev

FROM build AS test

RUN apt-get update && apt-get install gcovr lcov -y

RUN cmake -S . -B build_dev -DBUILD_TESTING=On -DCODE_COVERAGE=On \
    && cmake --build build_dev --parallel $(nproc) \
    && ctest --test-dir build_dev -T Test

# Generate coverage only from the main library (not tests and dependencies)
# TODO: figure out why lcov is throwing inconsitency and negative errors. For now, ignore those errors.
RUN lcov --capture --directory build_dev/CMakeFiles/dhtnet.dir/src --output-file build_dev/coverage_all.info --ignore-errors inconsistent,negative \
    && lcov --extract build_dev/coverage_all.info '/dhtnet/src/*' --output-file build_dev/coverage.info \
    && lcov --list build_dev/coverage.info > /result.summary \
    && mkdir -p /coverage \
    && genhtml build_dev/coverage.info --output-directory /coverage
