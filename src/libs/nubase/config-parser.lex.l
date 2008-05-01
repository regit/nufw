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

%x incl

%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "config-parser.yacc.h"

/* C declarations */

extern char *path;
extern char *filename;
static char *includefile;

/* For handling the 'include' directive*/
#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE includes[MAX_INCLUDE_DEPTH];
char *filenames[MAX_INCLUDE_DEPTH];
int includes_index = 0;

static char *escape_str(char *str)
{
	int i = -1;
	size_t strsize;
	char *ret;

	if (!(strsize = strlen(str))) return "";
	ret = malloc(strsize - 2);

	while (*str) ret[i++] = *str++;

        ret[i-1] = '\0';

	return ret;
}

static int can_append_path(char *str)
{

	if ((str[0] == '/') || ((str[0] == '.') && (str[1] == '.'))) {
		return 0;
	}

	return 1;

}

%}

SECTION		\[.*\]
SQSTRING	\'([^\\\']|\\.)*\'
DQSTRING	\"([^\\\"]|\\.)*\"
STRING		(\"|\')([^\\(\"|\')]|\\.)*(\"|\')
INCLUDE		include
COMMENT		^#.*\n
WORD		([a-zA-Z0-9_\-]+(\(\-?[0-9\*]+\))?\.?)+
EQUAL		\=
VOID		[ \t\n]+

%%

{INCLUDE}	{ BEGIN(incl); }

{WORD}		{	yylval.string = strdup(yytext);
			return TOK_WORD; }
{EQUAL}		{ return TOK_EQUAL; }

{SECTION}	{
			yylval.string = escape_str(yytext);
			return TOK_SECTION;
		}

{STRING}	{
			yylval.string = escape_str(yytext);
			return TOK_WORD;
		}

{COMMENT}	{
			/* We don't care */
		}

{VOID}		{
			/* We don't care */
		}


<incl>[ \t]*      /* eat the whitespace */
<incl>[^ \t\n]+	{ /* got the include file name */
		  if (includes_index >= MAX_INCLUDE_DEPTH) {
			  yyerror("Includes nested too deeply");
			  exit(1);
		  }

		  filenames[includes_index] = filename;
		  includes[includes_index++] = YY_CURRENT_BUFFER;

		filename = escape_str(yytext);

		if (can_append_path(filename)) {
			printf("We get %s/%s\n", path, filename);
//			sprintf(includefile,
//					"%s/%s", path, filename);
		}

		  yyin = fopen(filename, "r");
		  if (!yyin) {
			printf("Can not open %s\n", includefile);
			exit(1);
		  }
		  yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));

                  BEGIN(INITIAL);
		}
<<EOF>>		{
		  if (--includes_index < 0)
			  yyterminate();
		  else {
			  free(filenames[includes_index + 1]);
			  filename = filenames[includes_index];
			  yy_delete_buffer(YY_CURRENT_BUFFER);
			  yy_switch_to_buffer(includes[includes_index]);
		  }
		}

%%

int
yywrap(void)
{
	/* If supporting multiple files, update yyin here. */
	return 1;
}

