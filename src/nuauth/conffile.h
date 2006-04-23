/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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

#ifndef CONFFILE_H
#define CONFFILE_H

#define DEFAULT_CONF_FILE   CONFIG_DIR "/nuauth.conf"

typedef struct Conf_Params
{
  gchar *name;
  /*  guint token; */
  guint value_type;
  gint v_int;
  gchar * v_char;
} confparams;

/* hash table to stock variable def */
GHashTable * confvarlist;

/* use to add a conf var in the previous hash */
#define ADD_CONF_VAR(VAR,TYPE) g_hash_table_insert(confvarlist,g_strdup (#VAR),VAR)

/* functions */

int parse_conffile(char * filename,gint array_size,confparams symbols[]);
gpointer get_confvar_value(confparams symbols[],gint array_size,gchar * confparam);
int free_confparams(confparams symbols[],gint array_size);

#endif
