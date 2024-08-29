FROM ubuntu:22.04 AS build

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
        libssl-dev libfmt-dev libasio-dev libmsgpack-dev libyaml-cpp-dev \
        libupnp-dev libnatpmp-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

COPY . dhtnet

WORKDIR dhtnet

RUN git submodule update --init --recursive

RUN mkdir build_dev && cd build_dev \
	&& cmake .. -DBUILD_DEPENDENCIES=On -DCMAKE_INSTALL_PREFIX=/usr \
	&& make -j && make install

FROM build AS test

RUN apt-get update && apt-get install gcovr lcov -y

RUN cd build_dev \
    && cmake -DBUILD_TESTING=On -DCODE_COVERAGE=On .. \
    && make -j \
    && ctest -T Test -T Coverage \
    && ctest -T coverage > /result.summary

# Generate HTML report
RUN cd build_dev/CMakeFiles/dhtnet.dir \
    && lcov --capture --no-external --directory /dhtnet --output-file coverage.info \
    && mkdir /coverage \
    && genhtml coverage.info --output-directory /coverage