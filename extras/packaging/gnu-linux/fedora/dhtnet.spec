Name:           dhtnet
Version:        0.3.0
Release:        %autorelease
Summary:        Lightweight peer-to-peer communication library
License:        GPL-3.0-or-later
URL:            https://git.jami.net/savoirfairelinux/dhtnet
Source:         ./dhtnet-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  cmake
BuildRequires:  pkgconfig(opendht)
BuildRequires:  pkgconfig(libpjproject)
BuildRequires:  pkgconfig(fmt)
BuildRequires:  pkgconfig(yaml-cpp)
BuildRequires:  pkgconfig(systemd)
BuildRequires:  pkgconfig(natpmp)
BuildRequires:  pkgconfig(libupnp)
%global __requires_exclude ^pkgconfig\\((libpjproject|opendht)\\)$

%description
Toolkit to establish secure peer-to-peer connections identified by public
keys and traverse NAT without relying on central servers.

%package devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description devel
Development headers and pkg-config file for applications using %{name}.

%prep
%autosetup

%build
%cmake \
    -DBUILD_TESTING=OFF \
    -DBUILD_BENCHMARKS=OFF \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_DEPS_STATIC=ON \
    -DDNC_SYSTEMD=ON
%cmake_build

%install
%cmake_install

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%license COPYING
%doc README.md
%{_bindir}/dnc
%{_bindir}/dvpn
%{_bindir}/dsh
%{_bindir}/peerDiscovery
%{_bindir}/upnpctrl
%{_bindir}/dhtnet-crtmgr
%{_mandir}/man1/dnc.1.*
%{_mandir}/man1/dsh.1.*
%{_mandir}/man1/dvpn.1.*
%{_mandir}/man1/dhtnet-crtmgr.1.*
%{_libdir}/libdhtnet.so.*
%config(noreplace) %{_sysconfdir}/dhtnet/dnc.yaml
%{_unitdir}/dnc.service
%{_presetdir}/dhtnet-dnc.preset

%files devel
%{_includedir}/dhtnet/
%{_libdir}/libdhtnet.so
%{_libdir}/pkgconfig/dhtnet.pc

%post
mkdir -p /etc/dhtnet
echo "===================="
echo "dnc server installed."
echo "To configure your dnc client and/or server, run:"
echo "  dhtnet-crtmgr --interactive"
echo "Server configuration is in /etc/dhtnet/dnc.yaml"
echo "After configuration, enable and start server with:"
echo "  systemctl enable dnc.service"
echo "  systemctl start dnc.service"
echo "===================="

%changelog
%autochangelog
