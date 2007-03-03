all: command.py

edit = sed \
        -e 's,@localstatedir\@,$(localstatedir),g' \
        -e 's,@prefix\@,$(prefix),g'

command.py: command.py.in
	rm -f command.py command.py.tmp
	$(edit) command.py.in > command.py.tmp
	mv command.py.tmp command.py

clean:
	rm -f command.py command.py.tmp
