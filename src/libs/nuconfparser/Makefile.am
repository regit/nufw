noinst_LTLIBRARIES = libnuconfparser.la

EXTRA_DIST = config-parser.h t1.conf t1_included.conf

AM_CPPFLAGS = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase
BUILT_SOURCES = config-parser.yacc.h
AM_YFLAGS = -d

libnuconfparser_la_SOURCES =			\
		config-parser.yacc.y	\
		config-parser.lex.l

check_PROGRAMS = t_conf1 t_conf2

TESTS = ${check_PROGRAMS}

t_conf1_SOURCES = t_conf1.c
t_conf1_LDADD = libnuconfparser.la ../nubase/libnubase.la

t_conf2_SOURCES = t_conf2.c
t_conf2_LDADD = libnuconfparser.la ../nubase/libnubase.la

