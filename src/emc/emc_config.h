/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
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

#ifndef __EMC_CONFIG_H__
#define __EMC_CONFIG_H__

#define EMC_DEFAULT_CONF	CONFIG_DIR "/emc.conf"

/** \brief Default port EMC will listen to
 */
#define EMC_DEFAULT_PORT	"4140"

/** \brief Default value for maximum number of worker threads.
 */
#define EMC_DEFAULT_MAX_WORKERS	32

int emc_init_config(const char *filename);

char *emc_config_table_get(const char *key);
char *emc_config_table_get_alwaysstring(char *key);
char *emc_config_table_get_or_default(char *key, char *replace);
int emc_config_table_get_or_default_int(char *key, int defint);
void emc_config_table_destroy(void);

#endif /* __EMC_CONFIG_H__ */
