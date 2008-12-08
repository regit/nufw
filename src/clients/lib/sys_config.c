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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nubase.h>

#include "sys_config.h"
#include "getdelim.h"

#define SYS_CONF_FILE CONFIG_DIR "/nuclient.conf"

static int config_loaded = 0;
static char* default_hostname = NULL;
static char* default_port = NULL;
static char* default_tls_ca = NULL;
static char* default_tls_cert = NULL;
static char* default_tls_key = NULL;
static char* default_tls_crl = NULL;
static int default_suppress_fqdn_verif = 0;

#ifdef FREEBSD
#include "getdelim.h"

static char *strndup(const char* s, size_t n)
{
	char *new;
	size_t len = strlen(s);

	if (len > n)
		len = n;

	new = (char *) malloc (len + 1);
	if (new == NULL)
		return NULL;

	new[len] = '\0';
	return (char *) memcpy (new, s, len);
}

static ssize_t getline(char **lineptr, size_t * n, FILE * stream)
{
	return getdelim(lineptr, n, '\n', stream);
}
#endif /* #ifdef FREEBSD */

static int str_to_bool(const char *val, int default_value)
{
	if ( (!strcasecmp(val,"1")) ||
	     (!strcasecmp(val,"true")) ||
	     (!strcasecmp(val,"yes")) )
		return 1;

	if ( (!strcasecmp(val,"0")) ||
	     (!strcasecmp(val,"false")) ||
	     (!strcasecmp(val,"no")) )
		return 0;

	return default_value;
}

char *compute_user_config_path()
{
	char path_dir[254];
	char *home = nu_get_home_dir();
	if (home == NULL)
		return NULL;
	secure_snprintf(path_dir, sizeof(path_dir), "%s/.nufw", home);
	if (access(path_dir, R_OK) != 0) {
		return NULL;
	}
	secure_snprintf(path_dir, sizeof(path_dir), "%s/.nufw/nuclient.conf", home);
	free(home);
	if (access(path_dir, R_OK) != 0) {
		return NULL;
	}
	return strdup(path_dir);
}

static void replace_value(char ** initval, char *newval)
{
	if (! initval) {
		return;
	}

	if (*initval) {
		free(*initval);
	}
	*initval = newval;
}

int parse_sys_config(const char *filename)
{
	char *opt, *val, *line;
	size_t len;
	FILE * file;
	int line_nbr = 0;
	line = NULL;

	file = fopen(filename, "r");
	if (!file)
		return 0;

	printf("Loading settings from %s\n", filename);

	while (getline(&line, &len, file) >= 0) {
		char* equ_pos;
		line_nbr++;
		if (strlen(line) == 0 || *line == '#' || *line == '\n' )
			continue;

		equ_pos = strchr(line,'=');
		if (equ_pos == NULL) {
			fprintf(stderr, "Wrong format on line %i: %s\n",line_nbr, line);
			continue;
		}

		opt = strndup(line, equ_pos - line);
		val = strdup(equ_pos + 1);

		if (strlen(val) >= 1)
			val[strlen(val)-1] = '\0'; /* Strip '\n' */

		if (!strcmp(opt, "nuauth_ip"))
			replace_value(&default_hostname, val);
		else
		if (!strcmp(opt, "nuauth_port"))
			replace_value(&default_port, val);
		else
		if (!strcmp(opt, "nuauth_tls_ca"))
			replace_value(&default_tls_ca, val);
		else
		if (!strcmp(opt, "nuauth_tls_cert"))
			replace_value(&default_tls_cert, val);
		else
		if (!strcmp(opt, "nuauth_tls_key"))
			replace_value(&default_tls_key, val);
		else
		if (!strcmp(opt, "nuauth_tls_crl"))
			replace_value(&default_tls_crl, val);
		else
		if (!strcmp(opt, "nuauth_suppress_fqdn_verif")) {
			default_suppress_fqdn_verif = str_to_bool(val,1);
			free(val);
		}
		else {
			printf("warning: unknown option '%s' in config file\n", opt);
			free(val);
		}
		free(opt);
	}
	if (line)
		free(line);
	fclose(file);
	return 1;
}

void load_sys_config()
{
	char* user_config;

	if (config_loaded)
		return;

	config_loaded = 1;

	parse_sys_config(SYS_CONF_FILE);
	user_config = compute_user_config_path();
	if (user_config) {
		if (!parse_sys_config(user_config)) {
			fprintf(stderr,
				"Warning: unable to parse config file \"%s\"\n",
				user_config);
			free(user_config);
			return;
		}
	}
	free(user_config);
}

const char* nu_client_default_hostname()
{
	return default_hostname;
}

const char* nu_client_default_port()
{
	return 	default_port;
}

const char* nu_client_default_tls_ca()
{
	return 	default_tls_ca;
}

const char* nu_client_default_tls_cert()
{
	return 	default_tls_cert;
}

const char* nu_client_default_tls_key()
{
	return 	default_tls_key;
}

const char* nu_client_default_tls_crl()
{
	return 	default_tls_crl;
}

int nu_client_default_suppress_fqdn_verif()
{
	return 	default_suppress_fqdn_verif;
}
