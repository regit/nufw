#!/bin/sh

# Option details:
#
# -unrecog: SPlint doesn't read /usr/include/asm-generic/errno.h
#           (haypo doesn't understand why)
#
# -nullassign: that's because gcry_threads_gthread initialize some functions
#              to NULL (gcrypt_init.h)

splint \
    -I /usr/lib/gcc-lib/i486-linux-gnu/3.3.6/include/ \
    -I /usr/include/glib-2.0/ -I /usr/include/glib-2.0/glib \
    -I /usr/lib/glib-2.0/include/ \
    -I ../include/ -I ./ -I ./include/ \
    -warnposix \
    -unrecog \
    -nullassign \
    authsrv.c

