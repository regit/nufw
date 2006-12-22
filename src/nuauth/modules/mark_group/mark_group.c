/* $Id$ */

/*
** Copyright(C) 2006, INL
**	Written by Victor Stinner <vstinner@inl.fr>
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
#include <glib.h>
#include <ctype.h>
#include <limits.h>

typedef struct {
    /** Identifier of the group */
    uint32_t id;

    /** The mark (truncated the 'nbits' bits) */
    uint32_t mark;
} group_mark_t;

typedef struct {
    /** position of the mark (in bits) in the packet mark */
    unsigned int shift;

    /** mask to remove current mark of the packet */
    uint32_t mask;

    /** default mark if no group does match */
    uint32_t default_mark;

    /** list of group with a known mark */
    GList *groups;
} mark_group_config_t;

#define SHL32(x, n) (((n) < 32)?((x) << (n)):0)
#define SHR32(x, n) (((n) < 32)?((x) >> (n)):0)

/**
 * Convert a string to a 32-bit integer, skip spaces before.
 * Returns 0 on error, 1 otherwise.
 */
int str2int32(const char *text, uint32_t *value)
{
    long long_value;
    char *err;

    /* skip spaces */
    while (isspace(*text)) text++;

    long_value = strtol(text, &err, 10);
    if (err == NULL || *err != '\0')
        return 0;
    if ((long_value < INT_MIN) || (INT_MAX < long_value))
        return 0;
    *value = long_value;
    return 1;
}

/**
 * Parse group list file. Line format is "gid1,gid2,...,gidn:mark",
 * where gid and mark are integers in [0; 4294967295].
 *
 * Spaces are not allowed between group name and ":", but are allowed
 * between ":" and mark.
 */
void parse_group_file(mark_group_config_t *config, const char *filename)
{
    FILE* file=fopen(filename, "r");
    unsigned int line_number = 0;
    char line[4096];

    if (file == NULL)
    {
        /* fatal error, exit nuauth! */
        g_error("mark_group: Unable to open group list (file %s)!",
                filename);
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *separator = strchr(line, ':');
        char *mark_str;
        group_mark_t *group;
        size_t len;
        uint32_t group_id;
        uint32_t mark;
        gchar** groups_list;
        gchar** groups_item;

        /* update line number */
        line_number++;

        /* remove \n at the end of the line */
        len = strlen(line);
        if (0 < len && line[len-1] == '\n') line[len-1] = 0;

        if (line[0] == 0) {
            /* skip empty lines */
            continue;
        }

        /* find separator */
        if (separator == NULL) {
            log_message (SERIOUS_WARNING, AREA_MAIN,
                    "mark_group:%s:%u: Unable to find separator ':' in group list, stop parser.",
                    filename, line_number);
            break;
        }

        /* read mark */
        *separator = 0;
        mark_str = separator+1;
        if (!str2int32(separator+1, &mark))
        {
            log_message (WARNING, AREA_MAIN,
                    "mark_group:%s:%u: Invalid mark (%s), skip line.",
                    filename, line_number, separator+1);
            continue;
        }

        groups_list=g_strsplit(line,",",0);
        groups_item = groups_list;
        while ( *groups_item) {
            /* read group */
            if (!str2int32(*groups_item, &group_id)){
                log_message (WARNING, AREA_MAIN,
                        "mark_group:%s:%u: Invalid group identifier (%s), skip line.",
                        filename, line_number, *groups_item);
                continue;
            }

            /* add group */
            group = g_new(group_mark_t, 1);
            group->id = group_id;
            group->mark = mark;
            config->groups = g_list_append(config->groups, group);
            groups_item++;
        }
        g_strfreev(groups_list);
    }
    fclose(file);
}

/**
 * Load configuration of the module
 */
G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
    confparams vars[] = {
        { "mark_group_group_file", G_TOKEN_STRING, 0, g_strdup(MARK_GROUP_CONF) },
        { "mark_group_shift", G_TOKEN_INT, 0, NULL },
        { "mark_group_nbits", G_TOKEN_INT, 32, NULL },
        { "mark_group_default_mark", G_TOKEN_INT, 0, NULL },
    };
    const int nb_vars = sizeof(vars) / sizeof(confparams);
    const char *configfile=DEFAULT_CONF_FILE;
    mark_group_config_t* config = g_new0(mark_group_config_t, 1);
    unsigned int nbits;
    char *group_filename;

    /* parse config file */
    if (module->configfile){
        configfile = module->configfile;
    }
    parse_conffile(configfile, nb_vars, vars);

#define READ_CONF(KEY) \
    get_confvar_value(vars, nb_vars, KEY)
#define READ_CONF_INT(VAR, KEY, DEFAULT) \
    do { gpointer vpointer = READ_CONF(KEY); if (vpointer) VAR = *(int *)vpointer; else VAR = DEFAULT;} while (0)

    /* read options */
    group_filename = READ_CONF("mark_group_group_file");
    READ_CONF_INT(nbits, "mark_group_nbits", 32);
    READ_CONF_INT(config->shift, "mark_group_shift", 0);
    READ_CONF_INT(config->default_mark, "mark_group_default_mark", 0);

    /* free config struct */
    free_confparams(vars, nb_vars);

    /* create mask to remove nbits at position shift */
    config->mask = SHR32(0xFFFFFFFF, 32 - config->shift) | SHL32(0xFFFFFFFF, nbits + config->shift);

    /* parse group list */
    parse_group_file(config, group_filename);
    free(group_filename);

    /* store config and exit */
    module->params = config;
    return TRUE;
}

/**
 * Function called when the module is unloaded: free memory
 */
G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params)
{
    mark_group_config_t* config = params;
    if (config) {
        GList *iter;
        /* free list content */
        for (iter=config->groups; iter != NULL; iter = iter->next)
        {
            g_free(iter->data);
        }
        /* free list container */
        g_list_free(config->groups);
    }
    g_free(config);
    return TRUE;
}

/**
 * Check if one of the user groups of the connection match our group
 * with mark. If yes use the mark, otherwise use default mark.
 *
 * Change the mark of the packet in all cases.
 */
nu_error_t finalize_packet(connection_t* conn, gpointer params)
{
    mark_group_config_t* config = params;
    uint32_t mark = config->default_mark;
    GList *iter;

    /*
     * Search first matching group with mark and
     * stop when first group match
     */
    for (iter=config->groups; iter != NULL; iter = iter->next)
    {
        GSList *result;
        group_mark_t *group = iter->data;

        /* group in one of the user groups */
        result = g_slist_find(conn->user_groups, GUINT_TO_POINTER(group->id));
        if (result)
        {
            mark = group->mark;
            break;
        }
    }

    conn->mark = (conn->mark & config->mask) \
               | ((mark << config->shift) & ~config->mask);
    return NU_EXIT_OK;
}

