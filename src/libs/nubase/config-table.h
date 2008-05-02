/*
 ** Copyright(C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
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

#ifndef _CONFIG_TABLE_H_
#define _CONFIG_TABLE_H_

#include "linuxlist.h"

struct config_table_t {
	struct llist_head list;
	void *key;
	void *value;
} config_table_t;

char *nubase_config_table_get(char *key);
char *nubase_config_table_get_alwaysstring(char *key);

struct config_table_t *nubase_config_table_append(char *key, char *value);
struct config_table_t *nubase_config_table_set(char *key, char *value);

#endif /* _CONFIG_TABLE_H_ */

