Name:     dhtnet
Version:  0.3.0
Release:  %autorelease
Summary:  DHTNet, a Lightweight Peer-to-Peer Communication Library
License:  GPL-2.0+ AND BSL-1.0 AND GPL-3.0+ AND BSD-3-Clause AND Apache-2.0 AND Expat AND LGPL-2.0+
URL:      https://git.jami.net/savoirfairelinux/dhtnet
Source:   ./dhtnet-%{version}.tar.gz
BuildRequires: gcc
BuildRequires: g++
BuildRequires: make
BuildRequires: cmake

%description
DHTNet, a Lightweight Peer-to-Peer Communication Library,
allows you to connect with a device simply by knowing its public key and
efficiently manages peer discovery and connectivity establishment, including NAT traversal.

%prep
%autosetup

%build
%configure
%make_build

%install
%make_install

%files
%{_bindir}/dnc
%{_bindir}/dvpn
%{_bindir}/dsh
%{_bindir}/peerDiscovery
%{_bindir}/bench
%{_bindir}/upnpctrl
%{_bindir}/dhtnet-crtmgr
%{_mandir}/man1/dnc.1.*
%{_mandir}/man1/dsh.1.*
%{_mandir}/man1/dvpn.1.*
%{_mandir}/man1/dhtnet-crtmgr.1.*
%{_includedir}/dhtnet/*
%{_sysconfdir}/dhtnet/*

%changelog
%autochangelog