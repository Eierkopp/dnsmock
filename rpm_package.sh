#!/bin/bash

set -x

NAME=dnsmock
WD=RPM_TMP
VERSION=`dpkg-parsechangelog -S version`

cd `dirname $0`

# ./make_venv.sh
[ -f $NAME ] || dnsmock_env/bin/python3 -m nuitka -j 4 -o dnsmock --show-scons --recurse-all dnsmock.py

SOURCE_DIR=`rpmbuild --eval "%{_sourcedir}"`
TOP_DIR=`rpmbuild --eval "%{_topdir}"`
mkdir -p $TOP_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

TAR_FILE=$SOURCE_DIR/$NAME.tar.bz2

[ -d $WD ] && rm -rf $WD
mkdir -p $WD/$NAME
mkdir -p $WD/$NAME/etc/dnsmock
cp -a config/logger.conf $WD/$NAME/etc/dnsmock
cp -a config/dnsmock.conf.sample $WD/$NAME/etc/dnsmock
mkdir -p $WD/$NAME/lib/systemd/system
cp -a config/dnsmock.service $WD/$NAME/lib/systemd/system
mkdir -p $WD/$NAME/usr/bin
cp -a dnsmock $WD/$NAME/usr/bin
sed -e "s/X-VERSION-X/$VERSION/" dnsmock.spec > $WD/$NAME/dnsmock.spec
mkdir -p $WD/$NAME/usr/share/doc/$NAME
cp -a LICENSE $WD/$NAME/usr/share/doc/$NAME

pushd $WD
tar -hcf $TAR_FILE $NAME
popd

rpmbuild -ta $TAR_FILE
