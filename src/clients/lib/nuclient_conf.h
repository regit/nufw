/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
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

#ifndef NUCLIENT_CONF_H
#define NUCLIENT_CONF_H

int nuclient_parse_configuration(const char *user_config, const char *global_config);



char *nuclient_config_table_get(const char *key);
char *nuclient_config_table_get_alwaysstring(char *key);
char *nuclient_config_table_get_or_default(char *key, char *replace);
int nuclient_config_table_get_or_default_int(char *key, int defint);
void nuclient_config_table_destroy(void);
void nuclient_config_table_print(void *userdata, void (*func)(void *data, char *keyeqval));
void nuclient_config_table_walk(void *userdata, void (*func)(void *data, char *key, char *val));

#endif /* NUCLIENT_CONF_H */

