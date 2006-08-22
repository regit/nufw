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
