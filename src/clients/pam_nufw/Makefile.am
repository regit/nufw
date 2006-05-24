#if BUILD_PAM_NUFW

@SET_MAKE@
LIBTOOL			= $(SHELL) $(top_builddir)/libtool
TITLE			= pam_nufw

LIBS			=

modulesdir		= /lib/security

pam_nufw_la_CFLAGS	= -I ../lib -I$(top_srcdir)/include $(DYNAMIC)

modules_LTLIBRARIES	= pam_nufw.la

AM_LDFLAGS = "-L../lib/"

pam_nufw_la_SOURCES	= pam_nufw.c
pam_nufw_la_LDFLAGS	= -avoid-version -module -lpam -lnuclient
pam_nufw_la_LIBADD	=

#noinst_LTLIBRARIES		= pam_mail.la pam_nufw.a



#EXTRA_DIST		= README

CLEANFILES		= *~ $(TITLE).so


clean-local:
	rm -rf static


#endif
