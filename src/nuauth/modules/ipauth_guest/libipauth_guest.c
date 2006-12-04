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

#define IP_AUTH_GUEST_USERNAME "guest"

struct ipauth_guest_params {
    gchar* username;
};

/**
 * @{ */


G_MODULE_EXPORT gchar* unload_module_with_params(gpointer params_p)
{
  struct ipauth_guest_params* params = (struct ipauth_guest_params*)params_p;

  g_free(params->username);
  g_free(params);
 
  return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  confparams ipauth_guest_vars[] = {
      { "ipauth_guest_username" , G_TOKEN_STRING, 0 , g_strdup(IP_AUTH_GUEST_USERNAME) },
  };
  char *configfile=DEFAULT_CONF_FILE;
  struct ipauth_guest_params* params = g_new0(struct ipauth_guest_params,1);

  /* parse conf file */
  if (module->configfile){
      parse_conffile(module->configfile,sizeof(ipauth_guest_vars)/sizeof(confparams),ipauth_guest_vars);
  } else {
      parse_conffile(configfile,sizeof(ipauth_guest_vars)/sizeof(confparams),ipauth_guest_vars);
  }
  /* set variables */

#define READ_CONF(KEY) \
  get_confvar_value(ipauth_guest_vars, sizeof(ipauth_guest_vars)/sizeof(confparams), KEY)

  params->username = (char *)READ_CONF("ipauth_guest_username");

#undef READ_CONF

  module->params=(gpointer)params;
  return TRUE;
}

G_MODULE_EXPORT gchar* ip_authentication(tracking_t * header,struct ipauth_guest_params* params)
{
    if (params->username){
        return g_strdup(params->username);
    } else {
        return NULL;
    }
}

/** @} */
