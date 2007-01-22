/*
 ** Copyright(C) 2004-2005 INL
 ** written by Eric Leblond <regit@inl.fr>
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
 * \ingroup AuthNuauthModules
 * \defgroup SystemModule PAM+NSS authentication module
 *
 * @{ */

/**
 * \file system.c
 *
 * \brief Core file for system module
 *
 */

#include "../../nuauth_gcrypt.h"

#include <pwd.h>
#include <security/pam_appl.h>

GStaticMutex pam_mutex;

GSList * getugroups (char *username, gid_t gid);

typedef struct _auth_pam_userinfo {
	char* name;
	const char* pw;
} auth_pam_userinfo;

gint system_convert_username_to_uppercase;
gint system_convert_username_to_lowercase;
gint system_pam_module_not_threadsafe;

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
    return NUAUTH_API_VERSION;
}

/* Init module system */
G_MODULE_EXPORT gchar* g_module_check_init(GModule *module)
{
  gpointer vpointer;
confparams system_nuauth_vars[] = {
  { "system_convert_username_to_uppercase", G_TOKEN_INT, 0, 0 },
  { "system_convert_username_to_lowercase", G_TOKEN_INT, 0, 0 },
  { "system_pam_module_not_threadsafe", G_TOKEN_INT, 1, 0 }
};

  system_convert_username_to_uppercase=0;
  system_convert_username_to_lowercase=0;
  /*  parse conf file */
  parse_conffile(DEFAULT_CONF_FILE,
          sizeof(system_nuauth_vars)/sizeof(confparams),
          system_nuauth_vars);
  /*  set variables */
  vpointer = get_confvar_value(system_nuauth_vars,
          sizeof(system_nuauth_vars)/sizeof(confparams),
          "system_convert_username_to_uppercase");
  system_convert_username_to_uppercase = *(int *)(vpointer);
 vpointer = get_confvar_value(system_nuauth_vars,
          sizeof(system_nuauth_vars)/sizeof(confparams),
          "system_convert_username_to_lowercase");
  system_convert_username_to_lowercase = *(int *)(vpointer);
  if (system_convert_username_to_lowercase && system_convert_username_to_uppercase){
    system_convert_username_to_lowercase=0;
    system_convert_username_to_uppercase=0;
    g_message("Can not convert simultaneously username to upper and lower case");
  }



  vpointer = get_confvar_value(system_nuauth_vars,
          sizeof(system_nuauth_vars)/sizeof(confparams),
          "system_pam_module_not_threadsafe");
  system_pam_module_not_threadsafe = *(int *)(vpointer);

  return NULL;
}



/**
 * auth_pam_talker: supply authentication information to PAM when asked
 *
 * Assumptions:
 *   A password is asked for by requesting input without echoing
 *   A username is asked for by requesting input _with_ echoing
 *
 */
	static
int auth_pam_talker(int num_msg,
		const struct pam_message ** msg,
		struct pam_response ** resp,
		void *appdata_ptr)
{
	unsigned short i = 0;
	auth_pam_userinfo *userinfo = (auth_pam_userinfo *) appdata_ptr;
	struct pam_response *response = 0;

	/* parameter sanity checking */
	if (!resp || !msg || !userinfo)
		return PAM_CONV_ERR;

	/* allocate memory to store response */
	response = malloc(num_msg * sizeof(struct pam_response));
	if (!response)
		return PAM_CONV_ERR;

	/* copy values */
	for (i = 0; i < num_msg; i++) {
		/* initialize to safe values */
		response[i].resp_retcode = 0;
		response[i].resp = 0;

		/* select response based on requested output style */
		switch (msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
				/* on memory allocation failure, auth fails */
				response[i].resp = g_strdup(userinfo->name);
				break;
			case PAM_PROMPT_ECHO_OFF:
				response[i].resp = g_strdup(userinfo->pw);
				break;
			default:
				if (response)
					g_free(response);
				return PAM_CONV_ERR;
		}
	}
	/* everything okay, set PAM response values */
	*resp = response;
	return PAM_SUCCESS;
}

static char* normalize_username(const char * username)
{
  /* compute user name */
  char * user = get_rid_of_domain(username);
  if (! user)
      return NULL;

  if (system_convert_username_to_uppercase){
      /* User need to be pass in upper case to winbind */
      g_strup(user);
  }
  if (system_convert_username_to_lowercase){
      /* User need to be pass in lower case to winbind */
      g_strdown(user);
  }

  return user;
}

/**
 * \brief user_check realise user authentication
 *
 * It has to be exported by all user authentication modules
 *
 *  \param username User name string
 *  \param pass User provided password
 *  \param passlen Password length
 *  \param params Pointer to the parameter of the module instance
 *  \return SASL_OK if password is correct, other return are authentication failure
 */

G_MODULE_EXPORT int user_check(const char *username, const char *pass
		,unsigned passlen, gpointer params)
{
	char* user;
	int ret;

    user=normalize_username(username);
    if (user == NULL){
        return SASL_BADAUTH;
    }

	if (pass != NULL) {
		auth_pam_userinfo userinfo;
		pam_handle_t *pamh;
		struct pam_conv conv_info = {&auth_pam_talker, &userinfo };

		userinfo.name=user;
		userinfo.pw=pass;

		if (system_pam_module_not_threadsafe){
			g_static_mutex_lock (&pam_mutex);
		}

		ret = pam_start("nuauth", user, &conv_info, &pamh);
		if (ret != PAM_SUCCESS){
			g_warning("Can not initiate pam, dying");
			return SASL_BADAUTH;
		}

		ret = pam_authenticate(pamh, 0);    /* is user really user? */
		/* check auth */
		if (ret != PAM_SUCCESS){
			log_message(INFO, AREA_AUTH, "Bad password for user \"%s\"",user);
			pam_end(pamh,PAM_DATA_SILENT);
			if (system_pam_module_not_threadsafe){
				g_static_mutex_unlock (&pam_mutex);
			}
			return SASL_BADAUTH;
		}
		pam_end(pamh,PAM_DATA_SILENT);

		if (system_pam_module_not_threadsafe){
			g_static_mutex_unlock (&pam_mutex);
		}

	}

	return SASL_OK;
}

G_MODULE_EXPORT uint32_t  get_user_id(const char *username,gpointer params)
{
	int ret;
    char* user;
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp=NULL;

    user=normalize_username(username);

	ret = getpwnam_r(user, &result_buf, buffer, sizeof(buffer), &result_bufp);
	if (ret != 0 || (! result_bufp)){
		return SASL_BADAUTH;
	}

	return result_bufp->pw_uid;
}

G_MODULE_EXPORT GSList * get_user_groups(const char *username,gpointer params)
{

	int ret;
    char* user;
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp=NULL;

    user=normalize_username(username);

	ret = getpwnam_r(user, &result_buf, buffer, sizeof(buffer), &result_bufp);
	if (ret != 0 || (! result_bufp)){
		return NULL;
	}

    return getugroups(user,result_bufp->pw_gid);
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  return TRUE;
}

/** @} */
