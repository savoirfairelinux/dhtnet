# Packaging and release

In `extras/packaging`, the `build_packages.sh` script will build packages for supported platforms. The OS argument must be provided. The platform architecture (arm64, x86, …) is unable to be specified as packages will only be compiled and built on the platform that the build runs on.

**Usage:**
```bash
extras/packaging/build_packages.sh -a  # -a or --all will build all platform which are known to be supported
extras/packaging/build_packages.sh -u  # -u or --ubuntu will build for all supported versions of Ubuntu
extras/packaging/build_packages.sh -u22 -d11  # -u22 will build for ubuntu 22.04 and -d11 will build for Debian 11
```
