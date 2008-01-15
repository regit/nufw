if BUILD_NUTCPC

bin_PROGRAMS = nutcpc

EXTRA_DIST = valgrind.sh valgrind.supp 

# nutcpc
nutcpc_SOURCES = nutcpc.c
nutcpc_CPPFLAGS = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nussl/ -I$(top_srcdir)/src/clients/lib/
nutcpc_LDFLAGS = -L$(top_builddir)/src/clients/lib/
nutcpc_LDADD = -lnuclient

check:
	$(top_builddir)/src/clients/nutcpc/nutcpc -V

endif
