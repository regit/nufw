#!/bin/bash

libtoolize --force
aclocal -I macros/
autoheader
autoconf
automake -a
