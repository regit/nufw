#!/bin/bash

aclocal -I macros/
autoheader
autoconf
automake -a
