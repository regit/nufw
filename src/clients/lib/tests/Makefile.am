EXTRA_DIST = dummy_client.c

check:
	gcc -o dummy_client $(srcdir)/dummy_client.c -I$(top_srcdir)/src/clients/lib/ -L$(top_srcdir)/src/clients/lib/ -lnuclient
	rm dummy_client
