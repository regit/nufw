CC=gcc
LIBS=-L../.libs/ -lnubase
CFLAGS=-I../ -I../../../include

all: conffile testnuparm strings

conffile: conffile.c
	$(CC) conffile.c -lnubase $(CFLAGS) $(LIBS) -o conffile

testnuparm: testnuparm.c
	$(CC) testnuparm.c -lnubase $(CFLAGS) $(LIBS) -o testnuparm

strings: strings.c
	$(CC) strings.c -lnubase $(CFLAGS) $(LIBS) -o strings
