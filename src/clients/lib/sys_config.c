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
#include "getdelim.h"

#define SYS_CONF_FILE CONFIG_DIR "/nuclient.conf"
#define USR_CONF_FILE "/.nufw/nuclient.conf"

#ifdef FREEBSD
#include "getdelim.h"

char *strndup(const char* s, size_t n)
{
	char *new;
	size_t len = strlen(s);
	
	if(len > n)
		len = n;

	new = (char *) malloc (len + 1);
	if (new == NULL)
		return NULL;
	
	new[len] = '\0';
	return (char *) memcpy (new, s, len);
}

ssize_t getline(char **lineptr, size_t * n, FILE * stream)
{
	return getdelim(lineptr, n, '\n', stream);
}
#endif /* #ifdef FREEBSD */

void load_config_file(nuauth_session_t *session, char* path)
{
	int line_nbr = 0;
	char *opt, *val, *line;
	size_t len;
	FILE* file ;

	/* Parse the file */
	printf("Loading default settings from %s\n", path);
	file = fopen(path, "r"); 
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
		{
			if(session->default_hostname)
				free(session->default_hostname);
			session->default_hostname = val;
		}
		else
		if(!strcmp(opt, "nuauth_port"))
		{
			if(session->default_port)
				free(session->default_port);
			session->default_port = val;
		}
		else
			free(val);
		free(opt);
	}
	if(line)
		free(line);
	fclose(file);
}

void load_sys_config(nuauth_session_t *session)
{
	char* home;
	char* home_config;

	/* Load system wide config file */
	load_config_file(session, SYS_CONF_FILE);

	/* Load user config file */
	home = nu_get_home_dir();
	if(!home)
		return;

	home_config = (char*) calloc( strlen(home) + strlen(USR_CONF_FILE) + 1, 1 );

	if(!home_config)
		return;

	strncpy(home_config, home, strlen(home));
	strncat(home_config, USR_CONF_FILE, strlen(USR_CONF_FILE));
	load_config_file(session, home_config);

	free(home);
	free(home_config);
}
