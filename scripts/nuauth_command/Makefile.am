all: nuauth_command.py

edit = sed \
        -e 's,@localstatedir\@,$(localstatedir),g' \
        -e 's,@prefix\@,$(prefix),g'

nuauth_command.py: nuauth_command.py.in
	rm -f nuauth_command.py nuauth_command.py.tmp
	$(edit) nuauth_command.py.in > nuauth_command.py.tmp
	mv nuauth_command.py.tmp nuauth_command.py
	chmod +x nuauth_command.py

clean:
	rm -f nuauth_command.py nuauth_command.py.tmp
