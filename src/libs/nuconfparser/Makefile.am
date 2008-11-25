noinst_LTLIBRARIES = libnuconfparser.la

EXTRA_DIST = config-parser.h

AM_CPPFLAGS = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase
BUILT_SOURCES = config-parser.yacc.h
AM_YFLAGS = -d

libnuconfparser_la_SOURCES =			\
		config-parser.yacc.y	\
		config-parser.lex.l

