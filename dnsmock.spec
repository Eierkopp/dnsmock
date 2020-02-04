#!/bin/bash

Summary: Mocking DNS proxy
Name: dnsmock
Version: 1.1
Release: 1
License: GPL2
URL: https://github.com/Eierkopp/dnsmock.git
Group: Applications/Internet
Packager: Eierkopp
Requires: bash, python3.7
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

[ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
cp -a etc lib usr $RPM_BUILD_ROOT

%post

addgroup --system --quiet dnsmock
adduser --system --disabled-login --quiet --group dnsmock
mkdir -p /var/log/dnsmock
chown dnsmock:dnsmock /var/log/dnsmock

%postun

deluser --quiet dnsmock

%files

%defattr(644, root, root, 755)

%config /etc/dnsmock
%attr(755, root, root) /usr/bin/dnsmock
%attr(644, root, root) /lib/systemd/system/dnsmock.service
%attr(644, root, root) /usr/share
