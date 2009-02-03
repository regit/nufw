/*
 ** Copyright 2005-2009 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
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

#include "nuclient_conf.h"

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


static int str_to_bool(const char *val, int default_value)
{
	if ( (!strcmp(val,"1")) ||
	     (!strcasecmp(val,"true")) ||
	     (!strcasecmp(val,"yes")) )
		return 1;

	if ( (!strcmp(val,"0")) ||
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

void nuclient_use_config()
{
	char *value;

	default_hostname = nuclient_config_table_get("nuauth_ip");
	default_port = nuclient_config_table_get("nuauth_port");
	default_tls_ca = nuclient_config_table_get("nuauth_tls_ca");
	default_tls_cert = nuclient_config_table_get("nuauth_tls_cert");
	default_tls_key = nuclient_config_table_get("nuauth_tls_key");
	default_tls_crl = nuclient_config_table_get("nuauth_tls_crl");

	value = nuclient_config_table_get("nuauth_suppress_fqdn_verif");
	if (value) {
		default_suppress_fqdn_verif = str_to_bool(value,1);
	}
}

void load_sys_config()
{
	char* user_config;

	if (config_loaded)
		return;

	config_loaded = 1;

	user_config = compute_user_config_path();
	if (nuclient_parse_configuration(user_config, SYS_CONF_FILE) == 0) {
		nuclient_use_config();
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
