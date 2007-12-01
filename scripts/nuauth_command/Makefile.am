if BUILD_NUAUTH_COMMAND

SUBDIRS = scripts nuauth_command

EXTRA_DIST = setup.py

install-exec-local:
	$(PYTHON) $(srcdir)/setup.py install --prefix $(prefix)

endif
