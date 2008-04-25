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
#include "config-parser.yacc.h"

/* C declarations */

static char *escape_str(char *str)
{
	int i = -1;
	size_t strsize;
	char *ret;

	if (!(strsize = strlen(str))) return "";
	ret = malloc(strsize);

	while (*str) ret[i++] = *str++;

        ret[i-1] = '\0';

	return ret;
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

{INCLUDE}	{
			return TOK_INCLUDE;
		}

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


%%

int
yywrap(void)
{
	/* If supporting multiple files, update yyin here. */
	return 1;
}

