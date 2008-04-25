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

#define YYERROR_VERBOSE

%}

%token TOK_EQUAL
%token	<string> TOK_WORD
%token           TOK_INCLUDE
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
		| config include
		;

section:		TOK_SECTION {
				printf("\n%s is a section\n", $1);
			}
			;
include:		TOK_INCLUDE TOK_WORD {
				printf("\nWe include the file %s\n", $2);
			}
			;
key_value:		TOK_WORD TOK_EQUAL TOK_WORD
			{
				printf("\nKey=%s,Value=%s\n", $1, $3);
			}
			;

%%
extern FILE *yyin;

#ifdef _UNIT_TEST_
int main(void)
{
	FILE *fp;

	fp = fopen("../../../conf/nuauth.conf", "r");
	if (!fp) {
		fprintf(stderr, "Cannot open ../../../conf/nuauth.conf");
		return 1;
	}

	yyin = fp;

	yyparse();

	fclose(yyin);

	return 0;
}
#endif

