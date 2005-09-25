# ------------------------------------------------------------------------- #
# NuFW Spec File
# ------------------------------------------------------------------------- #
%define _unpackaged_files_terminate_build_ 0
%define name nufw
%define version 1.0.13
%define release 1
%define _prefix     /usr
%define _sysconfdir /etc/nufw
%define _bindir     /usr/bin
%define _sbindir    /usr/sbin
%define _mandir     /usr/share/man
%define _libdir     /usr/lib
%define _includedir /usr/include
# ------------------------------------------------------------------------- #
Name: %{name}
Version: %{version}
Release: %{release}
Summary: NuFW Authentication Gateway Firewall
Group: Applications/Firewall
Packager: L|NUX <linux@doctorsmail.org>
License: GPL
URL: http://www.nufw.org
Source0: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Prefix: %{_prefix}
# ------------------------------------------------------------------------- #
%description
NuFW Binary Package...
# ------------------------------------------------------------------------- #
%prep
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
# ------------------------------------------------------------------------- #
%setup -qn %{name}-%{version}
# ------------------------------------------------------------------------- #
%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --with-user-mark  --with-mysql-log --with-pgsql-log --with-system-auth --with-ldap  --with-gdbm --with-ident --with-debug --mandir=%{_mandir} 
make
make check
# ------------------------------------------------------------------------- #
%install

rm -rf   $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/certs
mkdir -p $RPM_BUILD_ROOT%{_bindir}
mkdir -p $RPM_BUILD_ROOT%{_sbindir}
mkdir -p $RPM_BUILD_ROOT%{_libdir}
mkdir -p $RPM_BUILD_ROOT%{_libdir}/nuauth
mkdir -p $RPM_BUILD_ROOT%{_libdir}/nuauth/modules
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man3
mkdir -p $RPM_BUILD_ROOT%{_includedir}

cp -R conf/*                                                                 $RPM_BUILD_ROOT%{_sysconfdir}

# Installing Configuration Files !!

install -m 0644 conf/acls.nufw                                               %{_sysconfdir}
install -m 0644 conf/acls.schema                                             %{_sysconfdir}
install -m 0644 conf/nuaclgen.conf                                           %{_sysconfdir}
install -m 0644 conf/nuauth.conf                                             %{_sysconfdir}
install -m 0644 conf/nulog-before-0.9.6.mysql.dump                           %{_sysconfdir}
install -m 0644 conf/nulog-before-0.9.6.pgsql.dump                           %{_sysconfdir}
install -m 0644 conf/nulog.mysql.dump                                        %{_sysconfdir}
install -m 0644 conf/nulog.pgsql.dump                                        %{_sysconfdir}
install -m 0644 conf/nulog-v1-v2.mysql.dump                                  %{_sysconfdir}
install -m 0644 conf/nutop.conf                                              %{_sysconfdir}
install -m 0644 conf/timeranges.schema                                       %{_sysconfdir}
install -m 0644 conf/users-gdbm.nufw                                         %{_sysconfdir}
install -m 0644 conf/users-plaintext.nufw                                    %{_sysconfdir}
install -m 0644 conf/certs/admin@nufw.org-cert.pem                           %{_sysconfdir}
install -m 0644 conf/certs/admin@nufw.org-key.pem                            %{_sysconfdir}
install -m 0644 conf/certs/nuauth-cert.pem                                   %{_sysconfdir}
install -m 0644 conf/certs/nuauth-key.pem                                    %{_sysconfdir}
install -m 0644 conf/certs/NuFW-cacert.pem                                   %{_sysconfdir}
install -m 0644 conf/certs/nufw-cert.pem                                     %{_sysconfdir}
install -m 0644 conf/certs/nufw-key.pem                                      %{_sysconfdir}
install -m 0644 conf/certs/user@nufw.org-cert.pem                            %{_sysconfdir}
install -m 0644 conf/certs/user@nufw.org-key.pem                             %{_sysconfdir}

# Instaling Man Pages !!

install -m 0644 doc/nuaclgen.1                                               %{_mandir}/man1
install -m 0644 doc/nuauth.1                                                 %{_mandir}/man1
install -m 0644 doc/nufw.1                                                   %{_mandir}/man1
install -m 0644 doc/nufw_dbm.1                                               %{_mandir}/man1
install -m 0644 doc/nutcpc.1                                                 %{_mandir}/man1
install -m 0644 doc/nutop.1                                                  %{_mandir}/man1
install -m 0644 doc/libnuclient.3                                            %{_mandir}/man3

# Installing Binaries !!

install -m 0755 src/clients/nutcpc/nutcpc                                    %{_bindir}
install -m 0755 src/support/dbm/nufw_dbm                                     %{_bindir}
install -m 0755 src/nufw/nufw                                                %{_sbindir}
install -m 0755 src/nuauth/nuauth                                            %{_sbindir}

# Installing Include Files !!

install -m 0644 src/clients/lib/nuclient.h                                   %{_includedir}

# Installing Libraries !!

install -m 0644 src/clients/lib/.libs/libnuclient.a                           %{_libdir}
install -m 0755 src/clients/lib/.libs/libnuclient.so                          %{_libdir}
install -m 0755 src/clients/lib/.libs/libnuclient.so.0.0.0                    %{_libdir}
install -m 0755 src/clients/lib/.libs/libnuclient.la                          %{_libdir}
install -m 0755 src/clients/lib/.libs/libnuclient.so.0                        %{_libdir}
install -m 0644 src/nuauth/modules/dbm/.libs/libdbm.a                         %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/dbm/.libs/libdbm.la                        %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/dbm/.libs/libdbm.so                        %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/dbm/.libs/libdbm.so.0                      %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/dbm/.libs/libdbm.so.0.0.0                  %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ipauth_ident/.libs/libipauthident.la       %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ipauth_ident/.libs/libipauthident.so       %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ipauth_ident/.libs/libipauthident.so.0.0.0 %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/ipauth_ident/.libs/libipauthident.a        %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ipauth_ident/.libs/libipauthident.so.0     %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/ldap/.libs/libldap.a                       %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ldap/.libs/libldap.la                      %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ldap/.libs/libldap.so                      %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ldap/.libs/libldap.so.0                    %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/ldap/.libs/libldap.so.0.0.0                %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/log_mysql/.libs/libmysql.a                 %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_mysql/.libs/libmysql.la                %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_mysql/.libs/libmysql.so                %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_mysql/.libs/libmysql.so.0              %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_mysql/.libs/libmysql.so.0.0.0          %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/log_pgsql/.libs/libpgsql.a                 %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_pgsql/.libs/libpgsql.la                %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_pgsql/.libs/libpgsql.so                %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_pgsql/.libs/libpgsql.so.0              %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_pgsql/.libs/libpgsql.so.0.0.0          %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/log_syslog/.libs/libsyslog.a               %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_syslog/.libs/libsyslog.so.0            %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_syslog/.libs/libsyslog.la              %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_syslog/.libs/libsyslog.so              %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/log_syslog/.libs/libsyslog.so.0.0.0        %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/plaintext/.libs/libplaintext.a             %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/plaintext/.libs/libplaintext.so.0          %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/plaintext/.libs/libplaintext.la            %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/plaintext/.libs/libplaintext.so            %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/plaintext/.libs/libplaintext.so.0.0.0      %{_libdir}/nuauth/modules
install -m 0644 src/nuauth/modules/system/.libs/libsystem.a                   %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/system/.libs/libsystem.la                  %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/system/.libs/libsystem.so                  %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/system/.libs/libsystem.so.0                %{_libdir}/nuauth/modules
install -m 0755 src/nuauth/modules/system/.libs/libsystem.so.0.0.0            %{_libdir}/nuauth/modules

# Installing Package !!

make DESTDIR=$RPM_BUILD_ROOT install

# ------------------------------------------------------------------------- #
%clean
rm -rf $RPM_BUILD_ROOT
#mkdir -p %{_sysconfdir}
#mkdir -p %{_libdir}/nuauth/
#mkdir -p %{_libdir}/nuauth/modules/
# ------------------------------------------------------------------------- #
%files
%defattr (-,root,root,-)
%doc AUTHORS COPYING ChangeLog NEWS README TODO
%{_bindir}/nutcpc
%{_bindir}/nufw_dbm
%{_sbindir}/nufw
%{_sbindir}/nuauth
%{_includedir}/nuclient.h
%{_libdir}/*.so.*
%{_libdir}/lib*.a
%{_libdir}/lib*.la
%{_libdir}/nuauth/modules/*.so.*
%{_libdir}/nuauth/modules/lib*.a
%{_libdir}/nuauth/modules/lib*.la
%{_sysconfdir}/*.conf
%{_sysconfdir}/*.dump
%{_sysconfdir}/*.nufw
%{_sysconfdir}/*.schema
%{_sysconfdir}/certs/*.pem
%{_mandir}/man1/*.gz
%{_mandir}/man3/*.gz
# ------------------------------------------------------------------------- #
%post
/sbin/modprobe ip_queue
#/sbin/iptables -I OUTPUT ! -o lo -m state --state NEW -p all -j QUEUE
#openssl req -new -x509 -nodes -days 365 -out %{_sysconfdir}/nuauth.pem -keyout %{_sysconfdir}/nuauth.pem
# ------------------------------------------------------------------------- #
%postun
rm -rf /etc/nufw
# ------------------------------------------------------------------------- #
%ChangeLog
* Sat July 16 2005 L|NUX <linux@doctorsmail.org>
- Initial RPM Package.

