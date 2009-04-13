CONFIG_FILES = acls.nufw mark_field.conf mark_group.conf nuaclgen.conf nuauth.conf nuclient.conf nutop.conf periods.xml users-plaintext.nufw \
	nuauth.d/nuauth_ldap.conf nuauth.d/nuauth_mysql.conf nuauth.d/nuauth_pgsql.conf nuauth.d/nuauth_tls.conf nuauth.d/nuauth_tuning.conf \
	nuauth.d/nuauth_mark.conf nuauth.d/nuauth_krb5.conf \
	nufw.conf emc.conf
SQL_DUMP = nulog.ipv4.mysql.dump nulog.ipv6.mysql.dump nulog.pgsql.dump
LDAP_FILES = acls.schema timeranges.schema
AUTH_MYSQL_FILES = auth_mysql/auth_mysql.ipv4.mysql.dump auth_mysql/auth_mysql.ipv6.mysql.dump auth_mysql/check_net.mysql
CERT_FILES = certs/admin@nufw.org-cert.pem certs/admin@nufw.org-key.pem certs/nuauth-cert.pem certs/nuauth-key.pem certs/NuFW-cacert.pem certs/nufw-cert.pem certs/nufw-key.pem certs/user@nufw.org-cert.pem certs/user@nufw.org-key.pem 

EXTRA_DIST = $(CONFIG_FILES) $(SQL_DUMP) $(LDAP_FILES) $(AUTH_MYSQL_FILES) $(CERT_FILES)
