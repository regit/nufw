SUBDIRS = src scripts doc tests

EXTRA_DIST = conf doc patches python debian autogen.sh

func_tests:
	cd tests && ./test_all.py

install-exec-local:
	install -d $(sysconfdir)
	test -e $(sysconfdir)/nuauth.conf || install -m 600 $(top_srcdir)/conf/nuauth.conf $(sysconfdir)
	install -m 600 $(top_srcdir)/conf/certs/NuFW-cacert.pem \
            $(top_srcdir)/conf/certs/{nufw,nuauth}-{key,cert}.pem \
            $(sysconfdir)
	install -m 600 $(top_srcdir)/conf/acls.nufw $(sysconfdir)
	install -m 600 $(top_srcdir)/conf/users-plaintext.nufw $(sysconfdir)/users.nufw

