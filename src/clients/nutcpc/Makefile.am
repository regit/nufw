if BUILD_NUTCPC

bin_PROGRAMS = nutcpc

EXTRA_DIST = valgrind.sh valgrind.supp

# nutcpc
nutcpc_SOURCES = nutcpc.c
nutcpc_CPPFLAGS = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nussl/ -I$(top_srcdir)/src/clients/lib/
INCLUDES = -I$(top_srcdir)/src/libs/nubase
nutcpc_LDFLAGS = -L$(top_builddir)/src/clients/lib/
nutcpc_LDADD = -lnuclient -L$(top_builddir)/src/libs/nubase -lnubase

check:
	$(top_builddir)/src/clients/nutcpc/nutcpc -V

endif
