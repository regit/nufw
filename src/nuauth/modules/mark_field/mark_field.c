/*
** Copyright(C) 2007, INL
**	Written by Eric Leblond <eric@inl.fr>
**	Based on mark_group module by Victor Stinner
**
** $Id$
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 3 of the License.
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

#include "mark_field.h"
#include <glib.h>
#include <limits.h>

typedef struct {
	/** Identifier of the field */
	GPatternSpec* pattern;

	/** The mark (truncated the 'nbits' bits) */
	uint32_t mark;
} field_mark_t;

typedef struct {
	/** position of the mark (in bits) in the packet mark */
	unsigned int shift;

	/** field to match
	 *  - 0: match on application name (default)
	 *  - 1: match on osname
	 */
	gchar type;

	/** mask to remove current mark of the packet */
	uint32_t mask;

	/** default mark if no field does match */
	uint32_t default_mark;

	/** list of pattern with associated mark */
	GList *fields;
} mark_field_config_t;

/**
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

/**
 * Parse field list file. Line format is "mark:blob",
 * where mark is integer in [0; 4294967295] and blob is a
 * free character string
 *
 * Spaces are not allowed.
 */
void parse_field_file(mark_field_config_t * config, const char *filename)
{
	FILE *file = fopen(filename, "r");
	unsigned int line_number = 0;
	char line[4096];

	if (file == NULL) {
		/* fatal error, exit nuauth! */
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "mark_field: Unable to open field list (file %s)!",
			    filename);
		exit(EXIT_FAILURE);
	}

	config->fields = NULL;

	while (fgets(line, sizeof(line), file) != NULL) {
		char *separator = strchr(line, ':');
		field_mark_t *field;
		size_t len;
		uint32_t mark;

		/* update line number */
		line_number++;

		/* remove \n at the end of the line */
		len = strlen(line);
		if (0 < len && line[len - 1] == '\n')
			line[len - 1] = 0;

		if (line[0] == 0) {
			/* skip empty lines */
			continue;
		}

		/* find separator */
		if (separator == NULL) {
			log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
				    "mark_field:%s:%u: Unable to find separator ':' in field list, stop parser.",
				    filename, line_number);
			break;
		}

		/* read mark */
		*separator = 0;
		if (!str_to_uint32(line, &mark)) {
			log_message(WARNING, DEBUG_AREA_MAIN,
				    "mark_field:%s:%u: Invalid mark (%s), skip line.",
				    filename, line_number, line);
			continue;
		}

		field = g_new0(field_mark_t, 1);
		field->mark = mark;
		field->pattern = g_pattern_spec_new(separator+1);

		config->fields = g_list_append(config->fields, field);
	}
	fclose(file);
}

/**
 * Load configuration of the module
 */
G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	mark_field_config_t *config = g_new0(mark_field_config_t, 1);
	unsigned int nbits;
	char *field_filename;


	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Mark_field module ($Revision$)");

	/* read options */
	field_filename = nubase_config_table_get_or_default("mark_field_file", MARK_FIELD_CONF);
	nbits = nubase_config_table_get_or_default_int("mark_field_nbits", 32);
	config->shift = nubase_config_table_get_or_default_int("mark_field_shift", 0);
	config->type = nubase_config_table_get_or_default_int("mark_field_type", 0);
	if (config->type < 0 && config->type > 1) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"mark_field: found unknown type, resetting to 0"
			   );
	}
	config->default_mark = nubase_config_table_get_or_default_int("mark_field_default_mark", 0);

	/* create mask to remove nbits at position shift */
	config->mask =
	    SHR32(0xFFFFFFFF, 32 - config->shift) | SHL32(0xFFFFFFFF,
							  nbits +
							  config->shift);

	/* parse field list */
	parse_field_file(config, field_filename);
	free(field_filename);

	/* store config and exit */
	module->params = config;
	return TRUE;
}

/**
 * Function called when the module is unloaded: free memory
 */
G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params)
{
	mark_field_config_t *config = params;
	if (config) {
		GList *iter;
		/* free list content */
		for (iter = config->fields; iter != NULL;
		     iter = iter->next) {
			g_pattern_spec_free((
				(field_mark_t *)(iter->data))->pattern
					);
			g_free(iter->data);
		}
		/* free list container */
		g_list_free(config->fields);
	}
	g_free(config);
	return TRUE;
}

/**
 * Check if one of the user fields of the connection match our field
 * with mark. If yes use the mark, otherwise use default mark.
 *
 * Change the mark of the packet in all cases.
 */
G_MODULE_EXPORT nu_error_t finalize_packet(connection_t * conn, gpointer params)
{
	mark_field_config_t *config = params;
	uint32_t mark = config->default_mark;
	GList *iter;
	gchar *string;

	switch (config->type) {
		case 0:
			string = conn->app_name;
			break;
		case 1:
			string = conn->os_sysname;
			break;
		default:
			log_message(WARNING, DEBUG_AREA_MAIN,
					  "mark_field: found unknown type"
					  );
			return NU_EXIT_ERROR;
	}

	/*
	 * Search first matching field with mark and
	 * stop when first field match
	 */
	for (iter = config->fields; iter != NULL; iter = iter->next) {
		gboolean result;
		field_mark_t *field = iter->data;

		/* field in one of the user fields */
		result = g_pattern_match_string(
				((field_mark_t *)(iter->data))->pattern,
				string
				);
		if (result) {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
					  "mark_field: found mark %d for %s",
					  field->mark,
					  conn->app_name);
			mark = field->mark;
			break;
		}
	}

	conn->mark = (conn->mark & config->mask)
	    | ((mark << config->shift) & ~config->mask);
	return NU_EXIT_OK;
}
