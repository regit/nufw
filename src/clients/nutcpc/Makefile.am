if BUILD_NUTCPC

TESTS=nutcpc_version.sh

bin_PROGRAMS = nutcpc

# nutcpc
nutcpc_SOURCES = nutcpc.c
nutcpc_CPPFLAGS = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/clients/lib/
nutcpc_LDFLAGS = -L$(top_builddir)/src/clients/lib/
nutcpc_LDADD = -lnuclient

endif
