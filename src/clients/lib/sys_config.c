/*
 ** Copyright 2005 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id: checks.c 3968 2007-11-26 14:03:43Z lds $
 **
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

#include "sys_config.h"
#include <stdio.h>

#define SYS_CONF_FILE CONFIG_DIR "/nuclient.conf"

void load_sys_config(nuauth_session_t *session)
{
	int line_nbr = 0;
	char *opt, *val, *line;
	size_t len;
	FILE* file ;

	if(session->default_hostname)
		free(session->default_hostname);
	if(session->default_port)
		free(session->default_port);

	/* Parse the file */
	printf("Loading default settings from %s\n", SYS_CONF_FILE);
	file = fopen(SYS_CONF_FILE, "r"); 
	if(!file)
		return;

	line = NULL;
	while (getline(&line, &len, file) >= 0)
	{
		char* equ_pos;
		line_nbr++;
		if(strlen(line) == 0 || *line == '#' || *line == '\n' )
			continue;

		equ_pos = strchr(line,'=');
		if(equ_pos == NULL)
		{
			fprintf(stderr, "Wrong format on line %i: %s\n",line_nbr, line);
			continue;
		}

		opt = strndup(line, equ_pos - line);
		val = strdup(equ_pos + 1);

		if(strlen(val) >= 1)
			val[strlen(val)-1] = '\0'; /* Strip '\n' */

		if(!strcmp(opt, "nuauth_ip"))
			session->default_hostname = val;
		else
		if(!strcmp(opt, "nuauth_port"))
			session->default_port = val;
		else
			free(val);
		free(opt);
	}
	if(line)
		free(line);
	fclose(file);
}

