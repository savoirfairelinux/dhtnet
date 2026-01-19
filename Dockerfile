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
    clang-format cppcheck locales openjdk-17-jre-headless unzip xz-utils \
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

RUN echo 'sonar.host.url=https://sq1.sfl.io/' \
    > /opt/sonar-scanner/conf/sonar-scanner.properties

# Download plugins and abort scanner
RUN /opt/sonar-scanner/bin/sonar-scanner -D sonar.projectKey="" 2>&1 || true

COPY . dhtnet

WORKDIR dhtnet

RUN git submodule update --init --recursive

RUN mkdir build_dev && cd build_dev \
    && cmake .. -DBUILD_DEPENDENCIES=On -DCMAKE_INSTALL_PREFIX=/usr \
    && make -j && make install

FROM build AS sonar

ARG SONAR_AUTH_TOKEN
ARG GERRIT_CHANGE_NUMBER
ARG GERRIT_PATCHSET_NUMBER
ARG GERRIT_BRANCH
ARG GERRIT_REFSPEC

WORKDIR /dhtnet

# Debug: Check if token is set (without exposing it)
RUN if [ -z "$SONAR_AUTH_TOKEN" ]; then \
    echo "ERROR: SONAR_AUTH_TOKEN not provided as build argument"; \
    echo "Please build with: docker build --build-arg SONAR_AUTH_TOKEN=<token> --target sonar ."; \
    exit 1; \
    else \
    echo "SONAR_AUTH_TOKEN is set (length: ${#SONAR_AUTH_TOKEN} chars)"; \
    fi

# Run cppcheck and sonar analysis
RUN make -f Makefile.sonar all

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