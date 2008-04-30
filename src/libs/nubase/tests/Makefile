CC=gcc
LIBS=-L../.libs/ -lnubase
CFLAGS=-I../

all: conffile

conffile: conffile.c
	$(CC) conffile.c -lnubase $(CFLAGS) $(LIBS) -o conffile

