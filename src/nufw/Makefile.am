
AM_CPPFLAGS = -O2 -Wall -DLOCALE_STATE_DIR="$(localstatedir)"

sbin_PROGRAMS = nufw

# nufw
nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c  proto.h  structure.h\
		debug.c
LIBS = -lipq -lpthread
