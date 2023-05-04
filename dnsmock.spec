#!/bin/bash

Summary: Mocking DNS proxy
Name: dnsmock
Version: 1.0
Release: 1
License: GPL2
URL: https://github.com/Eierkopp/dnsmock.git
Group: Applications/Internet
Packager: Eierkopp
Requires: bash, python3
BuildRequires: python3
Source: dnsmock.tar.bz2
AutoReqProv: no

%description

DNS Proxy allowing to inject fake responses for configured queries.

%prep

echo Building into $RPM_BUILD_ROOT
echo =============================

%setup -n dnsmock

echo Setup

pwd

./make_venv.sh

[ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc/dnsmock
cp -a config/dnsmock.conf.sample $RPM_BUILD_ROOT/etc/dnsmock
cp -a config/dnsmock.conf.sample config/logger.conf $RPM_BUILD_ROOT/etc/dnsmock
mkdir -p $RPM_BUILD_ROOT/usr/bin
cp -a bin/dnsmock $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/dnsmock
cp -a LICENSE $RPM_BUILD_ROOT/usr/share/doc/dnsmock
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
cp -a config/dnsmock.service $RPM_BUILD_ROOT/lib/systemd/system

%post

adduser --system -M -U dnsmock
mkdir -p /var/log/dnsmock
chown dnsmock:dnsmock /var/log/dnsmock

%postun

grep dnsmock: /etc/passwd && userdel dnsmock

%files

%defattr(644, root, root, 755)

%config /etc/dnsmock
%attr(755, root, root) /usr/bin/dnsmock
%attr(644, root, root) /lib/systemd/system/dnsmock.service
%attr(644, root, root) /usr/share/doc/dnsmock
