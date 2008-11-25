EXTRA_DIST = dummy_client.c

check:
	gcc -o dummy_client $(srcdir)/dummy_client.c -I$(top_srcdir)/src/clients/lib/ -I$(top_srcdir)/src/libs/nussl -L$(top_builddir)/src/clients/lib/ -L$(top_builddir)/src/clients/lib/.libs -lnuclient
	rm dummy_client
