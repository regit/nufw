/*
** Copyright(C) 2007-2008 INL
**          written by Eric Leblond <regit@inl.fr>
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


#include <auth_srv.h>

#include "nuauthconf.h"

/**
 * \ingroup NuauthModules
 */

/**
 * @{ */

typedef struct {
	/** position (in bits) in the mark */
	unsigned int mark_shift;

	/** position (in bits) in the flag */
	unsigned int flag_shift;

	/** mask to insert new data in packet mark */
	uint32_t mark_mask;
} mark_flag_config_t;


/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	mark_flag_config_t *config = params_p;

	g_free(config);
	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	mark_flag_config_t *config = g_new0(mark_flag_config_t, 1);
	unsigned int nbits;

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Mark_flag module ($Revision$)");

	/* read options */
	nbits = nuauth_config_table_get_or_default_int("mark_flag_nbits", 16);
	config->mark_shift = nuauth_config_table_get_or_default_int("mark_flag_mark_shift", 0);
	config->flag_shift = nuauth_config_table_get_or_default_int("mark_flag_flag_shift", 0);

	config->mark_mask =
	    (SHR32(0xFFFFFFFF, 32 - config->mark_shift) | SHL32(0xFFFFFFFF,  nbits + config->mark_shift));

	/* store config and exit */
	module->params = config;
	return TRUE;
}

G_MODULE_EXPORT nu_error_t finalize_packet(connection_t * connection,
					   gpointer params)
{
#ifdef DEBUG_ENABLE
	uint32_t old_mark = connection->mark;
#endif
	uint32_t flag;

	mark_flag_config_t *config = (mark_flag_config_t *) params;

	flag = SHR32(connection->flags, config->flag_shift);
	flag = SHL32(flag, config->mark_shift);
	connection->mark = (connection->mark & config->mark_mask) | (flag & ~config->mark_mask);

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			"mark_flag: Set mark to %08X (mark mask=%08X, flag=%u), was %08X",
			connection->mark, config->mark_mask, connection->flags, old_mark);

	return NU_EXIT_OK;
}

/** @} */
