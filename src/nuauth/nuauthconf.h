/*
 ** Copyright(C) 2005-2008 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
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

#ifndef NUAUTHCONF_H
#define NUAUTHCONF_H

int init_nuauthconf(struct nuauth_params **);

int build_prenuauthconf(struct nuauth_params *prenuauthconf,
			char *gwsrv_addr, policy_t connect_policy);

gboolean nuauth_reload(int signal);

void free_nuauth_params(struct nuauth_params *data);

int nuauth_parse_configuration(const char *filename);


char *nuauth_config_table_get(const char *key);
char *nuauth_config_table_get_alwaysstring(char *key);
char *nuauth_config_table_get_or_default(char *key, char *replace);
int nuauth_config_table_get_or_default_int(char *key, int defint);
void nuauth_config_table_destroy(void);
void nuauth_config_table_print(void *userdata, void (*func)(void *data, char *keyeqval));


#endif
