#!/usr/bin/env python3
# build.py --- Convenience script for building and running DHTNET dependencies

# Copyright (C) 2023 Savoir-faire Linux Inc.
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
patch_path = os.path.abspath("patches/pjproject/0009-add-config-site.patch")


def build_and_install_opendht():
    print("Building and installing OpenDHT...")
    try:
        # Configure OpenDHT with CMake
        subprocess.run(["cmake", ".",
            "-DCMAKE_INSTALL_PREFIX=" + install_dir,
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_TESTING=OFF",
            "-DOPENDHT_PYTHON=OFF",
            "-DOPENDHT_TOOLS=OFF",
            "-DOPENDHT_DOCUMENTATION=OFF",
            "-DOPENDHT_HTTP=ON",
            "-DOPENDHT_PROXY_CLIENT=ON",
        ], cwd=opendht_dir, check=True)

        # Build and install OpenDHT
        subprocess.run(["make", "install"], cwd=opendht_dir, check=True)
        print("OpenDHT installed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error building or installing OpenDHT: %s", e)

def build_and_install_pjproject():
    # Build PJSIP libraries
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
        target_file = os.path.join(pjproject_dir, "pjlib/include/pj/config_site.h")

        # Check if the config_site.h file already exists
        if os.path.exists(target_file):
            print(f"Target file {target_file} already exists. Skipping patch.")
        else:
            patch_command = ["patch", "-p1", "-i", patch_path]
            subprocess.run(patch_command, cwd=pjproject_dir, check=True)

        subprocess.run(["make"], cwd=pjproject_dir, check=True)
        subprocess.run(["make", "install"], cwd=pjproject_dir, check=True)

        print("PJSIP libraries built successfully.")
    except subprocess.CalledProcessError as e:
        print("Error building PJSIP libraries: %s", e)

def build_and_install_restinio():
    try:
        restino_build_dir = restinio_dir + "/dev/"
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
            "."
        ]
        subprocess.run(cmake_command, cwd=restino_build_dir, check=True)
        subprocess.run(["make", "-j8"], cwd=restino_build_dir, check=True)
        subprocess.run(["make", "install"], cwd=restino_build_dir, check=True)

        print("restinio built and installed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error building or installing restinio: %s", e)

def main():
    # Create install directory if it doesn't exist
    if not os.path.exists(install_dir):
        os.makedirs(install_dir)
    # Build and install restinio
    build_and_install_restinio()

    # Build and install OpenDHT
    build_and_install_opendht()

    # Build and install pjproject
    build_and_install_pjproject()

    subprocess.run([f"for p in {install_dir}/lib/pkgconfig/*.pc; do ./pkg-static.sh $p; done"], shell=True, check=True)


if __name__ == "__main__":
    main()
