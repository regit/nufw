/* $Id$ */

/*
** Copyright(C) 2004 Mikael Berthe <mikael+nufw@lists.lilotux.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 2 of the License.
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

#include "mark_group.h"

typedef struct {
    gchar *group;
    uint32_t mark;
} group_mark_t;

typedef struct {
    unsigned int shift;
    unsigned int nbits;
    uint32_t default_mark;
    GList *groups;
} mark_group_config_t;

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
    mark_group_config_t* config = g_new0(mark_group_config_t, 1);
    config->shift = 0;
    config->nbits = 32;
    config->default_mark = 0;
    config->groups = NULL;
    module->params = config;
    return TRUE;
}


G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params)
{
    mark_group_config_t* config = params;
    if (config) {
        group_mark_t *group;
        GList *iter;
        for (iter=config->groups; iter != NULL; iter = iter->next)
        {
            group = iter->data;
            g_free(group->group);
        }
        g_list_free(config->groups);
    }
    g_free(config);
    return TRUE;
}


nu_error_t finalise_packet(connection_t* conn, gpointer params)
{
    conn->mark = 42;
    return NU_EXIT_OK;
}

