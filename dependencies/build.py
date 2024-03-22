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

import subprocess
import os

# Define paths and directories
opendht_dir = "opendht"
pjproject_dir = "pjproject"
restinio_dir = "restinio"
install_dir = os.path.abspath("install")

def build_and_install_restinio():
    # Setting flush=True because this script is called by CMake via the
    # execute_process function, which by default doesn't print the content
    # of standard output until the executed process returns.
    print("\nBuilding and installing RESTinio...", flush=True)
    try:
        restino_build_dir = os.path.join(restinio_dir, "dev", "cmake_build")
        cmake_command = [
            "cmake",
            f"-DCMAKE_INSTALL_PREFIX={install_dir}",
            "-DRESTINIO_TEST=OFF",
            "-DRESTINIO_SAMPLE=OFF",
            "-DRESTINIO_INSTALL_SAMPLES=OFF",
            "-DRESTINIO_BENCH=OFF",
            "-DRESTINIO_INSTALL_BENCHES=OFF",
            "-DRESTINIO_FIND_DEPS=ON",
            "-DRESTINIO_ALLOW_SOBJECTIZER=Off",
            "-DRESTINIO_USE_BOOST_ASIO=none",
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

def build_and_install_opendht():
    print("\nBuilding and installing OpenDHT...", flush=True)
    try:
        opendht_build_dir = os.path.join(opendht_dir, "build")
        cmake_command = [
            "cmake", "..",
            "-DCMAKE_INSTALL_PREFIX=" + install_dir,
            "-DCMAKE_PREFIX_PATH=" + install_dir, # For finding restinio
            "-DCMAKE_BUILD_TYPE=Release",
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
            f"--with-gnutls={install_dir}"
        ]
        subprocess.run(configure_command, cwd=pjproject_dir, check=True)
        subprocess.run(["make"], cwd=pjproject_dir, check=True)
        subprocess.run(["make", "install"], cwd=pjproject_dir, check=True)

        print("PJSIP libraries built successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print("Error building PJSIP libraries: %s", e)
        return False

def main():
    # Create install directory if it doesn't exist
    if not os.path.exists(install_dir):
        os.makedirs(install_dir)
    # Build and install restinio
    if not build_and_install_restinio():
        print("Error building or installing restinio.")
        return

    # Build and install OpenDHT
    if not build_and_install_opendht():
        print("Error building or installing OpenDHT.")
        return

    # Build and install pjproject
    if not build_and_install_pjproject():
        print("Error building or installing PJSIP libraries.")
        return

    subprocess.run([f"for p in {install_dir}/lib/pkgconfig/*.pc; do ./pkg-static.sh $p; done"], shell=True, check=True)


if __name__ == "__main__":
    main()
