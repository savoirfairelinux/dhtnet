FROM ubuntu:24.04 AS build

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
    clang-tidy unzip\
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Install SonarScanner
ARG SONAR_VERSION=6.2.1.4610
ARG SONAR_REPO=https://binaries.sonarsource.com/Distribution/sonar-scanner-cli
RUN set -x && \
    wget -O /tmp/sonar-scanner.zip "${SONAR_REPO}/sonar-scanner-cli-${SONAR_VERSION}.zip" && \
    cd /opt && \
    unzip /tmp/sonar-scanner.zip && \
    rm -f /tmp/sonar-scanner.zip

RUN ln -s "/opt/sonar-scanner-${SONAR_VERSION}" /opt/sonar-scanner

RUN echo 'sonar.host.url=https://sonar-jami.savoirfairelinux.net' \
    > /opt/sonar-scanner/conf/sonar-scanner.properties

# Download plugins and abort scanner
RUN /opt/sonar-scanner/bin/sonar-scanner -D sonar.projectKey="" 2>&1 || true

COPY . dhtnet

WORKDIR dhtnet

RUN git submodule update --init --recursive

RUN mkdir build_dev && cd build_dev \
    && cmake .. -DBUILD_DEPENDENCIES=On -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    && make -j && make install

FROM build AS sonar

WORKDIR /dhtnet/build_dev

# Run clang-tidy and generate report
RUN run-clang-tidy -p . > clang-tidy-report.txt || exit 0

FROM build AS test

RUN apt-get update && apt-get install gcovr lcov -y

RUN cd build_dev \
    && cmake -DBUILD_TESTING=On -DCODE_COVERAGE=On .. \
    && make -j \
    && ctest -T Test

# Generate coverage only from the main library (not tests and dependencies)
# TODO: figure out why lcov is throwing inconsitency and negative errors. For now, ignore those errors.
RUN cd build_dev \
    && lcov --capture --directory ./CMakeFiles/dhtnet.dir/src --output-file coverage_all.info --ignore-errors inconsistent,negative \
    && lcov --extract coverage_all.info '/dhtnet/src/*' --output-file coverage.info \
    && lcov --list coverage.info > /result.summary \
    && mkdir -p /coverage \
    && genhtml coverage.info --output-directory /coverage