<<<<<<< PATCH SET (e927ba packaging: add help text after install)
Name:     dhtnet
Version:  0.3.1
Release:  1
Summary:  DHTNet, a Lightweight Peer-to-Peer Communication Library
License:  GPL-2.0+ AND BSL-1.0 AND GPL-3.0+ AND BSD-3-Clause AND Apache-2.0 AND Expat AND LGPL-2.0+
URL:      https://git.jami.net/savoirfairelinux/dhtnet
Source:   ./dhtnet-%{version}.tar.gz
BuildRequires: gcc
BuildRequires: g++
BuildRequires: make
BuildRequires: cmake
%global __requires_exclude pkgconfig\\((libpjproject|opendht)\\)
%global debug_package %{nil}

%description
DHTNet, a Lightweight Peer-to-Peer Communication Library,
allows you to connect with a device simply by knowing its public key and
efficiently manages peer discovery and connectivity establishment, including NAT traversal.

%prep
%autosetup

%build
mkdir build
cd build
cmake .. -DBUILD_TESTING=OFF \
         -DBUILD_BENCHMARKS=OFF \
         -DBUILD_SHARED_LIBS=ON \
         -DDHTNET_LLHTTP=ON \
         -DDNC_SYSTEMD=ON \
         -DCMAKE_INSTALL_PREFIX=%{buildroot} \
         -DCMAKE_INSTALL_BINDIR=%{buildroot}%{_bindir} \
         -DCMAKE_INSTALL_MANDIR=%{buildroot}%{_mandir} \
         -DCMAKE_INSTALL_DOCDIR=%{buildroot}%{_docdir}/dhtnet \
         -DCMAKE_INSTALL_LIBDIR=%{buildroot}%{_libdir} \
         -DCMAKE_INSTALL_INCLUDEDIR=%{buildroot}%{_includedir} \
         -DCMAKE_INSTALL_SYSCONFDIR=%{buildroot}%{_sysconfdir} \
         -DDNC_SYSTEMD_UNIT_FILE_LOCATION=%{buildroot}/usr/lib/systemd/system \
         -DDNC_SYSTEMD_PRESET_FILE_LOCATION=%{buildroot}/usr/lib/systemd/system-preset

%install
cd build
make -j
make install

%files
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
%{_docdir}/dhtnet/*
%{_libdir}/*
%{_includedir}/dhtnet/*
%{_sysconfdir}/dhtnet/*
/usr/lib/systemd/system/dnc.service
/usr/lib/systemd/system-preset/dhtnet-dnc.preset

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
* Fri Sep 13 2024 Louis Maillard <louis.maillard@savoirfairelinux.com> - 0.3.1-1
- Fix path in packaging
- Add postinstall text to help setup

* Mon Jul 29 2024 Louis Maillard <louis.maillard@savoirfairelinux.com> - 0.3.0
- Include UPnP support

* Wed Jul 17 2024 Louis Maillard <louis.maillard@savoirfairelinux.com> - 0.2.0
- Initial release.
- Add binaries dnc, dhtnet-crmgr, dsh, dvpn
- Include documentation as man pages
- Dynamic library available as libdhtnet.so
=======
>>>>>>> BASE      (ff273f Revert "packaging: Add Fedora 40 and 39 support")
