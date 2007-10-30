if BUILD_NUAUTH_COMMAND

SUBDIRS = scripts nuauth_command

EXTRA_DIST = setup.py

install-exec-local:
	./setup.py install `test -n "$(DESTDIR)" && echo --prefix $(DESTDIR)`

endif
