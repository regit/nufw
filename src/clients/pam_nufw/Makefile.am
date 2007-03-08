if BUILD_PAM_NUFW

@SET_MAKE@
TITLE			= pam_nufw
modulesdir		= /lib/security

pam_nufw_la_CFLAGS	= -I ../lib -I$(top_srcdir)/include $(DYNAMIC)

modules_LTLIBRARIES	= pam_nufw.la

pam_nufw_la_SOURCES	= pam_nufw.c
pam_nufw_la_LDFLAGS	= -avoid-version -module
pam_nufw_la_LIBADD	= -L../lib/ -lpam -lnuclient

CLEANFILES		= *~ $(TITLE).so

clean-local:
	rm -rf static


endif
