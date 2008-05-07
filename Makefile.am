SUBDIRS = src scripts doc tests conf python

PATCH_FILES = patches/dump-connection-mark.diff 
EXTRA_DIST = autogen.sh $(PATCH_FILES)

func_tests:
	cd tests && ./test_all.py

all:
	@echo "Compile done";

install-data-am:
	@echo "Run 'make install-conf' if you want to install initial configuration file";

install-conf:
	install -d $(sysconfdir)
	test -e $(sysconfdir)/nuauth.conf || install -m 600 $(top_srcdir)/conf/nuauth.conf $(sysconfdir)
	test -e $(sysconfdir)/nuauth_ldap.conf || install -m 600 $(top_srcdir)/conf/nuauth_ldap.conf $(sysconfdir)
	test -e $(sysconfdir)/nuauth_tls.conf || install -m 600 $(top_srcdir)/conf/nuauth_tls.conf $(sysconfdir)
	test -e $(sysconfdir)/nuauth_mysql.conf || install -m 600 $(top_srcdir)/conf/nuauth_mysql.conf $(sysconfdir)
	test -e $(sysconfdir)/nuauth_pgsql.conf || install -m 600 $(top_srcdir)/conf/nuauth_pgsql.conf $(sysconfdir)
	test -e $(sysconfdir)/nuauth_tuning.conf || install -m 600 $(top_srcdir)/conf/nuauth_tuning.conf $(sysconfdir)
	test -e $(sysconfdir)/certs/NuFW-cacert.pem || install -m 600 $(top_srcdir)/conf/certs/NuFW-cacert.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nufw-key.pem || install -m 600 $(top_srcdir)/conf/certs/nufw-key.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nufw-cert.pem || install -m 600 $(top_srcdir)/conf/certs/nufw-cert.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nuauth-key.pem || install -m 600 $(top_srcdir)/conf/certs/nuauth-key.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nuauth-cert.pem || install -m 600 $(top_srcdir)/conf/certs/nuauth-cert.pem $(sysconfdir)
	test -e $(sysconfdir)/acls.nufw || install -m 600 $(top_srcdir)/conf/acls.nufw $(sysconfdir)
	test -e $(sysconfdir)/users.nufw || install -m 600 $(top_srcdir)/conf/users-plaintext.nufw $(sysconfdir)/users.nufw

