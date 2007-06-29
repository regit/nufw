if BUILD_NUTCPC

TESTS=nutcpc_version.sh

# Evil hack (because not portable) by haypo to make gcc (or ld or libtool)
# find libnuclient.so librar
AM_LDFLAGS = "-L../lib/"

bin_PROGRAMS = nutcpc

# nutcpc
nutcpc_SOURCES = nutcpc.c
nutcpc_LDADD = -lnuclient

endif
