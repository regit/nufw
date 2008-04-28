noinst_LTLIBRARIES = libnubase.la

EXTRA_DIST = ipv6.h log.h nubase.h packet_parser.h strings.h

AM_CPPFLAGS = -I$(top_srcdir)/src/include/
BUILT_SOURCES = config-parser.yacc.h
AM_YFLAGS = -d

#config-parser.yacc.y
#config-parser.lex.l
libnubase_la_SOURCES =			\
		log.c			\
		ipv6.c			\
		packet_parser.c		\
		strings.c

