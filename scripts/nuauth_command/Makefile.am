if BUILD_NUAUTH_COMMAND

SUBDIRS = scripts

install-exec-local:
	./setup.py install `test -n "$(DESTDIR)" && echo --prefix $(DESTDIR)`

endif
