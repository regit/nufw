/*
** Copyright(C) 2006 INL
**          written by Eric Leblond <regit@inl.fr>
**
** $Id$
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


#include <auth_srv.h>

/**
 * \ingroup NuauthModules
 */

/**
 * @{ */

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
    return NUAUTH_API_VERSION;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
    log_message(VERBOSE_DEBUG, AREA_MAIN,"Mark_uid module ($Revision$)");
	return TRUE;
}

G_MODULE_EXPORT nu_error_t finalize_packet (connection_t* connection,gpointer params)
{
	connection->mark = connection->user_id & 0xFFFF;
	return NU_EXIT_OK;
}

/** @} */
