%define _unpackaged_files_terminate_build 0
%define name nufw 
%define version 0.9.5
%define release 1
%define _prefix /usr/local/nufw
%define _manpath /usr/share/man
%define _sysconfdir /etc/nufw

Name:           %{name}
Version:        %{version}
Release:        %{release}
#Epoch:          0
Summary:        NuFW is an "authenticating gateway". This means it requires authentication for any connections to be forwarded through the gateway.
Group:          Applications/Firewall
Packager:       Farrukh Ahmed <f4fahmed@gmail.com>
License:        GPL
URL:            http://www.nufw.org
Source0:        /home/rpm/rpmbuild/rpm/SOURCES/nufw-0.9.5.tar.gz
#Source99:       <for original Red Hat or other upstream spec>
#Patch0:         
#Patch1:         
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Prefix: %{_prefix}

#---For kernel modules------------------------------------------------
# # "uname -r" output of the kernel to build for, the running one
# # if none was specified with "--define 'kernel <uname -r>'"
# %{!?kernel: %{expand: %%define        kernel          %(uname -r)}}
#
# %define       kversion        %(echo %{kernel} | sed -e s/smp// -)
# %define       krelver         %(echo %{kversion} | tr -s '-' '_')
# %if %(echo %{kernel} | grep -c smp)
#       %{expand:%%define ksmp -smp}
# %endif
#---------------------------------------------------------------------

#BuildRequires:  
#Requires:       

#Conflicts:      
#Obsoletes:      
#BuildConflicts: 
#Requires(pre,post): 

%description
NuFW Binary Package....

#%package        devel
#Summary:        
#Group:          Development/Libraries
#Requires:       %{name} = %{epoch}:%{version}-%{release}

#%description    devel
#<Long description of sub-package here>
#<Multiple lines are fine>

# -----------------------------------------------------------------------------

%prep
%setup -q

# -----------------------------------------------------------------------------

%build
# For QT apps: [ -n "$QTDIR" ] || . %{_sysconfdir}/profile.d/qt.sh
#%configure
#make %{?_smp_mflags}

#make test
#make check
if [ -x ./configure ]; then 
	CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{_prefix}
else
	CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh --prefix=%{_prefix}
fi
make
#make test
#make check 
# -----------------------------------------------------------------------------

%install
rm -rf $RPM_BUILD_ROOT
#%makeinstall
#%find_lang %{name}

make DESTDIR=$RPM_BUILD_ROOT install

#rm -f $RPM_BUILD_ROOT%{_infodir}/dir
#find $RPM_BUILD_ROOT -type f -name "*.la" -exec rm -f {} ';'

# -----------------------------------------------------------------------------

%clean
rm -rf $RPM_BUILD_ROOT

# -----------------------------------------------------------------------------

# ldconfig's for packages that install %{_libdir}/*.so.*
# -> Don't forget Requires(post,postun): /sbin/ldconfig
# ...and install-info's for ones that install %{_infodir}/*.info*
# -> Don't forget Requires(post,preun): /sbin/install-info

##%post -p /sbin/ldconfig
##/sbin/install-info %{_infodir}/%{name}.info %{_infodir}/dir 2>/dev/null || :

##%preun
##if [ $1 = 0 ]; then
##  /sbin/install-info --delete %{_infodir}/%{name}.info \
##    %{_infodir}/dir 2>/dev/null || :
##fi

#%postun -p /sbin/ldconfig

# -----------------------------------------------------------------------------

%files -f %{name}.lang
%defattr(-,root,root,-)
%doc AUTHORS COPYING ChangeLog NEWS README TODO
%{_prefix}/bin/nutcpc
%{_prefix}/bin/nufw_dbm
%{_prefix}/include/nuclient.h
%{_prefix}/lib/*.so.*
%{_prefix}/lib/lib*.a
%{_prefix}/lib/lib*.la
%{_prefix}/lib/nuauth/modules/*.so.*
%{_prefix}/lib/nuauth/modules/lib*.a
%{_prefix}/lib/nuauth/modules/lib*.la
%{_prefix}/man/man1/*.1
%{_prefix}/man/man3/*.3
%{_prefix}/sbin/nuauth
%{_prefix}/sbin/nufw


#%{_prefix}/etc
#%{_prefix}/etc/*.conf
#%{_prefix}/man[^3]/*

#%files devel
#%defattr(-,root,root,-)
#%doc HACKING
#%{_libdir}/*.a
#%{_libdir}/*.so
#%{_mandir}/man3/*

# -----------------------------------------------------------------------------

%changelog
* Sat Oct 16 2004 Farrukh Ahmed <f4fahmed@gmail.com> - epoch:version-release
- Initial RPM release.
