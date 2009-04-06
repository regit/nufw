/*
 ** Copyright(C) 2004-2009 INL
 ** written by Eric Leblond <regit@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

GStaticMutex pam_mutex = G_STATIC_MUTEX_INIT;

GSList *getugroups(char *username, gid_t gid);

typedef struct {
	char *name;
	const char *pw;
} auth_pam_userinfo;

gint system_pam_module_not_threadsafe;
extern gint system_glibc_cant_guess_maxgroups;
gint system_suppress_prefixed_domain;

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

/* Init module system */
G_MODULE_EXPORT gchar *g_module_check_init(GModule * module)
{

	/*  set variables */
	system_pam_module_not_threadsafe = nuauth_config_table_get_or_default_int("system_pam_module_not_threadsafe", 1);
	system_glibc_cant_guess_maxgroups = nuauth_config_table_get_or_default_int("system_glibc_cant_guess_maxgroups", 0);
	system_suppress_prefixed_domain = nuauth_config_table_get_or_default_int("system_suppress_prefixed_domain", 0);

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
		    const struct pam_message **msg,
		    struct pam_response **resp, void *appdata_ptr)
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

static char *normalize_username(const char *username)
{
	/* compute user name */
	char *user = get_rid_of_domain(username);
	if (!user)
		return NULL;

	if (system_suppress_prefixed_domain) {
		char *pv_user = get_rid_of_prefix_domain(user);
		g_free(user);
		user = pv_user;
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
 *  \param session pointer to the user_session_t:: that we working on
 *  \param params Pointer to the parameter of the module instance
 *  \return SASL_OK if password is correct, other return are authentication failure
 */

G_MODULE_EXPORT int user_check(const char *username, const char *pass,
			       user_session_t *session,
			       unsigned passlen, gpointer params)
{
	char *user;
	int ret;

	user = normalize_username(username);
	if (user == NULL) {
		return SASL_BADAUTH;
	}

	if (pass != NULL) {
		auth_pam_userinfo userinfo;
		pam_handle_t *pamh;
		struct pam_conv conv_info =
		    { &auth_pam_talker, &userinfo };

		userinfo.name = user;
		userinfo.pw = pass;

		if (system_pam_module_not_threadsafe) {
			g_static_mutex_lock(&pam_mutex);
		}
#ifdef PERF_DISPLAY_ENABLE
		{
			struct timeval tvstart, tvend, result;
			if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
				gettimeofday(&tvstart, NULL);
			}
#endif


			ret = pam_start("nuauth", user, &conv_info, &pamh);
			if (ret != PAM_SUCCESS) {
				g_warning("Can not initiate pam, dying");
				if (system_pam_module_not_threadsafe) {
					g_static_mutex_unlock(&pam_mutex);
				}
				return SASL_BADAUTH;
			}

			ret = pam_authenticate(pamh, 0);	/* is user really user? */
			/* check auth */
			if (ret != PAM_SUCCESS) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "Bad password for user \"%s\"",
					    user);
				pam_end(pamh, PAM_DATA_SILENT);
				if (system_pam_module_not_threadsafe) {
					g_static_mutex_unlock(&pam_mutex);
				}
				return SASL_BADAUTH;
			}
			pam_end(pamh, PAM_DATA_SILENT);

			if (system_pam_module_not_threadsafe) {
				g_static_mutex_unlock(&pam_mutex);
			}
#ifdef PERF_DISPLAY_ENABLE
			if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
				gettimeofday(&tvend, NULL);
				timeval_substract(&result, &tvend, &tvstart);
				log_message(INFO, DEBUG_AREA_PERF,
						"PAM Auth duration: %.1f msec",
						(double)result.tv_sec*1000+
							(double)(result.tv_usec/1000));
			}
		}
#endif


	}

	return SASL_OK;
}

G_MODULE_EXPORT uint32_t get_user_id(const char *username, gpointer params)
{
	int ret;
	char *user;
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp = NULL;

	user = normalize_username(username);

	if (system_pam_module_not_threadsafe) {
		g_static_mutex_lock(&pam_mutex);
	}
	ret = getpwnam_r(user, &result_buf, buffer, sizeof(buffer),
		       &result_bufp);
	if (system_pam_module_not_threadsafe) {
		g_static_mutex_unlock(&pam_mutex);
	}
	if (ret != 0 || (!result_bufp)) {
		g_free(user);
		return SASL_BADAUTH;
	}

	g_free(user);
	return result_bufp->pw_uid;
}

G_MODULE_EXPORT GSList *get_user_groups(const char *username,
					gpointer params)
{

	int ret;
	char *user;
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp = NULL;
	GSList *userlist = NULL;

	user = normalize_username(username);

	if (system_pam_module_not_threadsafe) {
		g_static_mutex_lock(&pam_mutex);
	}
	ret = getpwnam_r(user, &result_buf, buffer, sizeof(buffer),
		       &result_bufp);
	if (system_pam_module_not_threadsafe) {
		g_static_mutex_unlock(&pam_mutex);
	}
	if (ret != 0 || (!result_bufp)) {
		g_free(user);
		return NULL;
	}

	if (system_pam_module_not_threadsafe) {
		g_static_mutex_lock(&pam_mutex);
		userlist = getugroups(user, result_bufp->pw_gid);
		g_static_mutex_unlock(&pam_mutex);
	} else {
		userlist = getugroups(user, result_bufp->pw_gid);
	}
	g_free(user);
	return userlist;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "System module ($Revision$)");
	return TRUE;
}

/** @} */
