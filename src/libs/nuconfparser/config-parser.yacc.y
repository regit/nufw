/*
 ** Copyright (C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

#include <nubase.h>

#define YYERROR_VERBOSE

extern FILE *yyin;
const char *filename;
char *path;

/* Pass the argument to yyparse through to yylex. */
#define YYPARSE_PARAM parsed_config
#define YYLEX_PARAM   parsed_config

%}

%token TOK_EQUAL
%token	<string> TOK_WORD
%token	<string> TOK_SECTION
%token	<string> TOK_STRING

%union {
	char *string;
	int number;
}

%destructor { free ($$); } TOK_WORD TOK_SECTION

%locations
%pure_parser

%parse-param { struct llist_head* parsed_config }

%{

/* this must come after bison macros, since we need these types to be defined */
int yylex(YYSTYPE* lvalp, YYLTYPE* llocp, struct llist_head* parsed_config);

void yyerror(YYLTYPE* locp, struct llist_head *parsed_config, const char* err);


%}

%%
config:		 /* empty */
		| config section
		| config key_value
		;

section:		TOK_SECTION {
				printf("\n%s is a section\n", $1);
				free($1);
			}
			;
key_value:		TOK_WORD TOK_EQUAL TOK_WORD
			{
				nubase_config_table_append(parsed_config, $1,$3);
				free($1);
				free($3);
			}
		|
			TOK_WORD TOK_EQUAL TOK_STRING
			{
				nubase_config_table_append(parsed_config, $1,$3);
				free($1);
				free($3);
			}
			;

%%

void yyerror(YYLTYPE* locp, struct llist_head *parsed_config, const char* err)
{
	fprintf(stderr, "YYERROR:%s\n", err);
}

struct llist_head * parse_configuration(const char *config)
{
	struct llist_head * config_table_list;

	path = str_extract_until(config, '/');
	filename = config;

	yyin = fopen(config, "r");
	if ( ! yyin ) {
		fprintf(stderr, "Cannot open file %s.\n", config);
		return NULL;
	}
	config_table_list = malloc(sizeof(*config_table_list));
	INIT_LLIST_HEAD( config_table_list );

	yyparse(config_table_list);

	return config_table_list;
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

