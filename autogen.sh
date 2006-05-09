#!/bin/sh

libtoolize --force --automake

echo "Run aclocal"
aclocal -I macros/

echo "Run autoheader"
autoheader

echo "Run autoconf"
autoconf

echo "Run automake"
automake -a --copy

echo "Done."
echo
echo "Now type: ./configure"
echo "Help with: ./configure --help"
