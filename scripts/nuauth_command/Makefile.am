if BUILD_NUAUTH_COMMAND

SUBDIRS = scripts nuauth_command

EXTRA_DIST = setup.py

install-exec-local:
	$(PYTHON) $(srcdir)/setup.py install --prefix $(DESTDIR)$(prefix)

clean-local:
	$(PYTHON) $(srcdir)/setup.py clean; \
	rm -rf $(top_builddir)/scripts/nuauth_command/build

uninstall-local:
	[ ! -f "$(DESTDIR)$(prefix)/bin/nuauth_command" ] || rm -f "$(DESTDIR)$(prefix)/bin/nuauth_command"
	find "$(DESTDIR)$(prefix)/lib" -name "nuauth_command-*.egg-info" -delete ||true

endif
