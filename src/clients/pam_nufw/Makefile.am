if BUILD_PAM_NUFW

@SET_MAKE@
TITLE			= pam_nufw
modulesdir		= /lib/security

pam_nufw_la_CFLAGS	= -I$(top_srcdir)/src/clients/lib -I$(top_srcdir)/src/libs/nussl -I$(top_srcdir)/src/include $(DYNAMIC)

modules_LTLIBRARIES	= pam_nufw.la

pam_nufw_la_SOURCES	= pam_nufw.c
pam_nufw_la_LDFLAGS	= -avoid-version -module -L$(top_srcdir)/src/clients/lib/
pam_nufw_la_LIBADD	= -lpam ../lib/libnuclient.la

CLEANFILES		= *~ $(TITLE).so

clean-local:
	rm -rf static


endif
