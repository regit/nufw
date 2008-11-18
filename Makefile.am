SUBDIRS = src scripts doc tests conf python selinux

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
	install -d $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.conf || install -m 600 $(top_srcdir)/conf/nuauth.conf $(sysconfdir)
	test -e $(sysconfdir)/nuauth.d/nuauth_ldap.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_ldap.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_tls.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_tls.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_mysql.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_mysql.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_pgsql.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_pgsql.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_tuning.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_tuning.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_mark.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_mark.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_krb5.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_krb5.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/nuauth.d/nuauth_authtype.conf || install -m 600 $(top_srcdir)/conf/nuauth.d/nuauth_authtype.conf $(sysconfdir)/nuauth.d
	test -e $(sysconfdir)/certs/NuFW-cacert.pem || install -m 600 $(top_srcdir)/conf/certs/NuFW-cacert.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nufw-key.pem || install -m 600 $(top_srcdir)/conf/certs/nufw-key.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nufw-cert.pem || install -m 600 $(top_srcdir)/conf/certs/nufw-cert.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nuauth-key.pem || install -m 600 $(top_srcdir)/conf/certs/nuauth-key.pem $(sysconfdir)
	test -e $(sysconfdir)/certs/nuauth-cert.pem || install -m 600 $(top_srcdir)/conf/certs/nuauth-cert.pem $(sysconfdir)
	test -e $(sysconfdir)/acls.nufw || install -m 600 $(top_srcdir)/conf/acls.nufw $(sysconfdir)
	test -e $(sysconfdir)/users.nufw || install -m 600 $(top_srcdir)/conf/users-plaintext.nufw $(sysconfdir)/users.nufw
	test -e $(sysconfdir)/periods.xml || install -m 600 $(top_srcdir)/conf/periods.xml $(sysconfdir)/

