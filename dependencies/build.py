#!/usr/bin/env python3
# build.py --- Convenience script for building and running DHTNET dependencies

# Copyright (C) 2023-2024 Savoir-faire Linux Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

import argparse
import subprocess
import os

# Define paths and directories
opendht_dir = "opendht"
pjproject_dir = "pjproject"
restinio_dir = "restinio"
msgpack_dir = "msgpack"
install_dir = os.path.abspath("install")

def build_and_install_restinio(cxx_std):
    # Setting flush=True because this script is called by CMake via the
    # execute_process function, which by default doesn't print the content
    # of standard output until the executed process returns.
    print("\nBuilding and installing RESTinio...", flush=True)
    try:
        restino_build_dir = os.path.join(restinio_dir, "dev", "cmake_build")
        cmake_command = [
            "cmake",
            f"-DCMAKE_INSTALL_PREFIX={install_dir}",
            f"-DCMAKE_CXX_STANDARD={cxx_std}",
            "-DRESTINIO_TEST=Off",
            "-DRESTINIO_SAMPLE=Off",
            "-DRESTINIO_BENCHMARK=Off",
            "-DRESTINIO_WITH_SOBJECTIZER=Off",
            "-DRESTINIO_DEP_STANDALONE_ASIO=system",
            "-DRESTINIO_DEP_LLHTTP=system",
            "-DRESTINIO_DEP_FMT=system",
            "-DRESTINIO_DEP_EXPECTED_LITE=system",
            ".."
        ]
        os.makedirs(restino_build_dir, exist_ok=True)
        subprocess.run(cmake_command, cwd=restino_build_dir, check=True)
        subprocess.run(["make", "-j8"], cwd=restino_build_dir, check=True)
        subprocess.run(["make", "install"], cwd=restino_build_dir, check=True)

        print("RESTinio built and installed successfully.")
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        print("Error building or installing restinio:", e)
        return False

def build_and_install_opendht(cxx_std):
    print("\nBuilding and installing OpenDHT...", flush=True)
    try:
        opendht_build_dir = os.path.join(opendht_dir, "build")
        cmake_command = [
            "cmake", "..",
            "-DCMAKE_INSTALL_PREFIX=" + install_dir,
            "-DCMAKE_PREFIX_PATH=" + install_dir, # For finding restinio
            f"-DCMAKE_CXX_STANDARD={cxx_std}",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_TESTING=OFF",
            "-DOPENDHT_PYTHON=OFF",
            "-DOPENDHT_TOOLS=OFF",
            "-DOPENDHT_DOCUMENTATION=OFF",
            "-DOPENDHT_HTTP=ON",
            "-DOPENDHT_PROXY_CLIENT=ON",
        ]
        os.makedirs(opendht_build_dir, exist_ok=True)
        subprocess.run(cmake_command, cwd=opendht_build_dir, check=True)
        subprocess.run(["make", "install"], cwd=opendht_build_dir, check=True)
        print("OpenDHT installed successfully.")
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        print("Error building or installing OpenDHT:", e)
        return False

def build_and_install_pjproject():
    print("\nBuilding and installing PJSIP...", flush=True)
    try:
        configure_command = [
            "./configure",
            f"--prefix={install_dir}",
            "--disable-sound",
            "--enable-video",
            "--enable-ext-sound",
            "--disable-speex-aec",
            "--disable-g711-codec",
            "--disable-l16-codec",
            "--disable-gsm-codec",
            "--disable-g722-codec",
            "--disable-g7221-codec",
            "--disable-speex-codec",
            "--disable-ilbc-codec",
            "--disable-opencore-amr",
            "--disable-silk",
            "--disable-sdl",
            "--disable-ffmpeg",
            "--disable-v4l2",
            "--disable-openh264",
            "--disable-resample",
            "--disable-libwebrtc",
            f"--with-gnutls={install_dir}",
            'CFLAGS=-fPIC',
        ]
        subprocess.run(configure_command, cwd=pjproject_dir, check=True)
        subprocess.run(["make"], cwd=pjproject_dir, check=True)
        subprocess.run(["make", "install"], cwd=pjproject_dir, check=True)

        print("PJSIP libraries built successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print("Error building PJSIP libraries: %s", e)
        return False

def build_and_install_msgpack(cxx_std):
    print("\nBuilding and installing msgpack...", flush=True)
    try:
        msgpack_build_dir = os.path.join(msgpack_dir, "build")
        cmake_command = [
            "cmake", "..",
            "-DCMAKE_INSTALL_PREFIX=" + install_dir,
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            f"-DMSGPACK_CXX{cxx_std}=ON",
            "-DMSGPACK_USE_BOOST=OFF",
            "-DMSGPACK_BUILD_EXAMPLES=OFF",
        ]
        os.makedirs(msgpack_build_dir, exist_ok=True)
        subprocess.run(cmake_command, cwd=msgpack_build_dir, check=True)
        subprocess.run(["make", "install"], cwd=msgpack_build_dir, check=True)
        print("msgpack installed successfully.")
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        print("Error building or installing msgpack:", e)
        return False

def download_and_install_expected_lite():
    print("\nDownloading and installing expected-lite...", flush=True)
    os.makedirs(f"{install_dir}/include/nonstd", exist_ok=True)
    subprocess.run([f"wget https://raw.githubusercontent.com/martinmoene/expected-lite/master/include/nonstd/expected.hpp -O {install_dir}/include/nonstd/expected.hpp"], shell=True, check=True)

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="DHTNet dependencies build script")
    parser.add_argument('--build-msgpack', default=False, action='store_true')
    parser.add_argument('--std', default='20', help='C++ Standard (e.g. 17, 20)')
    args = parser.parse_args()

    # Create install directory if it doesn't exist
    if not os.path.exists(install_dir):
        os.makedirs(install_dir)

    # Download and install expected-lite
    download_and_install_expected_lite()

    # Build and install restinio
    if not build_and_install_restinio(args.std):
        print("Error building or installing restinio.")
        return

    # Build and install msgpack if necessary
    if args.build_msgpack:
        if not build_and_install_msgpack(args.std):
            print("Error building or installing msgpack.")
            return

    # Build and install OpenDHT
    if not build_and_install_opendht(args.std):
        print("Error building or installing OpenDHT.")
        return

    # Build and install pjproject
    if not build_and_install_pjproject():
        print("Error building or installing PJSIP libraries.")
        return

    subprocess.run([f"for p in {install_dir}/lib/pkgconfig/*.pc; do ./pkg-static.sh $p; done"], shell=True, check=True)


if __name__ == "__main__":
    main()
