/*
** Copyright(C) 2006 INL
**          written by Eric Leblond <regit@inl.fr>
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
#include "session_uid.h"

/**
 * \ingroup NuauthModules
 */

/**
 * @{ */

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
  struct xml_defs_params* params=(struct xml_defs_params*)params_p;
  /*  Free user list */
  if (params){
      g_free(params->xml_defs_periodfile);
  }
  g_free(params);
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{

}

G_MODULE_EXPORT nu_error_t user_session_modify (user_session_t* session,gpointer params)
{
	session->tcmark = session->tcmark & 0xffff0000;
}

/** @} */
