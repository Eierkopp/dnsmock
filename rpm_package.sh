#!/bin/bash

NAME=dnsmock

cd `dirname $0`

SOURCE_DIR=`rpmbuild --eval "%{_sourcedir}"`
TOP_DIR=`rpmbuild --eval "%{_topdir}"`
mkdir -p $TOP_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

TAR_FILE=$SOURCE_DIR/$NAME.tar.bz2

tar -C .. -hcf $TAR_FILE $NAME/config $NAME/dnsmocklib $NAME/LICENSE $NAME/dnsmock.py $NAME/dnsmock.spec $NAME/make_venv.sh $NAME/requirements.txt

rpmbuild -ba dnsmock.spec
