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
import logging

# Configure the logging system
logging.basicConfig(filename='install.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define paths and directories
opendht_dir = "opendht"
pjproject_dir = "pjproject"
install_dir = os.path.abspath("install")

def build_and_install_opendht():
    logging.info("Building and installing OpenDHT...")
    try:
        # Configure OpenDHT with CMake
        subprocess.run(["cmake", ".", "-DCMAKE_INSTALL_PREFIX=" + install_dir], cwd=opendht_dir, check=True)

        # Build and install OpenDHT
        subprocess.run(["make", "install"], cwd=opendht_dir, check=True)
        logging.info("OpenDHT installed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error("Error building or installing OpenDHT: %s", e)

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
        subprocess.run(["make"], cwd=pjproject_dir, check=True)
        subprocess.run(["make", "install"], cwd=pjproject_dir, check=True)

        logging.info("PJSIP libraries built successfully.")
    except subprocess.CalledProcessError as e:
        logging.error("Error building PJSIP libraries: %s", e)

def main():
    # Create install directory if it doesn't exist
    if not os.path.exists(install_dir):
        os.makedirs(install_dir)

    # Build and install OpenDHT
    build_and_install_opendht()

    # Build and install pjproject
    build_and_install_pjproject()

if __name__ == "__main__":
    main()
