/*
 ** Copyright(C) 2006 INL
 **	written by Eric Leblond <regit@inl.fr>
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
#include <auth_srv.h>

/**
 * \ingroup NuauthModules
 */

/**
 * @{ */


G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
	return TRUE;
}

G_MODULE_EXPORT int user_session_modify(user_session_t* session, gpointer params)
{
    if (nuauthconf->session_duration){
        session->expire=time(NULL)+nuauthconf->session_duration;
    } else {
        session->expire=-1;
    }
    return SASL_OK;
}

/** @} */
