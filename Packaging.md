# Packaging and release

In `extras/packaging`, you will find a `build_packages.sh` script which will build packages for supported plateform. You must provide as argument the OS for which you want to build. You can't specify the plateform (arm64, x86, ...) as you can compile only for the same plateform as the one you are running on.

**Usage:**
```bash
extras/packaging/build_packages.sh -a  # -a or --all will build all plateform which are known to be supported
extras/packaging/build_packages.sh -u  # -u or --ubuntu will build for all supported versions of Ubuntu
extras/packaging/build_packages.sh -u22 -d11  # -u22 will build for ubuntu 22.04 and -d11 will build for Debian 11
```
