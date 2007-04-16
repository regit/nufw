all: nuauth_command

edit = sed \
        -e 's,@localstatedir\@,$(localstatedir),g' \
        -e 's,@prefix\@,$(prefix),g'

nuauth_command: nuauth_command.in
	rm -f nuauth_command nuauth_command.tmp
	$(edit) nuauth_command.in > nuauth_command.tmp
	mv nuauth_command.tmp nuauth_command
	chmod +x nuauth_command

clean:
	rm -f nuauth_command nuauth_command.tmp
