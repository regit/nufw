/*
 ** Copyright (C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
%{
#include <stdio.h>
#include <errno.h>

#include "hash.h"

extern int yylex(void);
extern void yylex_init(void);
extern void yylex_destroy(void);
extern void yyerror(char *);
extern void *yy_scan_string(const char *);
extern void yy_delete_buffer(void *);

#define YYERROR_VERBOSE

char *filename;

%}

%token TOK_EQUAL
%token	<string> TOK_WORD
%token	<string> TOK_SECTION
%token	<string> TOK_STRING

%union {
	char *string;
	int number;
}

%%
config:		 /* empty */
		| config section
		| config key_value
		;

section:		TOK_SECTION {
				printf("\n%s is a section\n", $1);
			}
			;
key_value:		TOK_WORD TOK_EQUAL TOK_WORD
			{
				nubase_hash_append($1,$3);
			}
			;

%%

void yyerror(char *str)
{
	fprintf(stderr, "YYERROR:%s\n", str);
}

int
__parse_configuration(FILE *input, char *name)
{
	extern FILE *yyin;

	filename = name;
	yyin = input;
	yyparse();
	return  0;
}

int parse_configuration(char *config)
{
	FILE *fp;

	fp = fopen(config, "r");
	if ( ! fp ) {
		fprintf(stderr, "Cannot open file %s.\n", config);
		return 1;
	}

	return __parse_configuration(fp, config);
}


#ifdef _UNIT_TEST_
/* gcc config-parser.lex.c config-parser.yacc.c -o config-parser -D_UNIT_TEST_ -ly -lfl */
int main(void)
{
#if 0
	FILE *fp;

	fp = fopen("../../../conf/nuauth.conf", "r");
	if (!fp) {
		fprintf(stderr, "Cannot open ../../../conf/nuauth.conf");
		return 1;
	}

	parse_configuration(fp, "../../../conf/nuauth.conf");
#endif
	parse_configuration("../../../conf/nuauth.conf");

	return 0;
}
#endif

