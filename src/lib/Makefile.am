# SSL abstration library

AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/

noinst_LIBRARIES = libcssl.a

libcssl_a_SOURCES = ssl.c

LIBS = $(GLIB_LIBS) -lssl
