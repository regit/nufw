/*
 ** Copyright(C) 2004 INL
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

#include "../../nuauth_gcrypt.h"

#include <pwd.h>
#include <security/pam_appl.h>

GSList * getugroups (char *username, gid_t gid);

typedef struct _auth_pam_userinfo {
	char* name;
	char* pw;
} auth_pam_userinfo;

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


G_MODULE_EXPORT int user_check(const char *username, const char *pass
		,unsigned passlen, uint16_t *userid, GSList **groups)
{
	char* user;
	int ret; 
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp=NULL;

	/* compute user name */
	user = get_rid_of_domain(username);
	if (! user)
		return SASL_BADAUTH;

	if (pass != NULL) {
		auth_pam_userinfo userinfo;
		pam_handle_t *pamh;
		struct pam_conv conv_info = {&auth_pam_talker, &userinfo };


		userinfo.name=user;
		userinfo.pw=pass;
		
		ret = pam_start("nuauth", user, &conv_info, &pamh);
		if (ret != PAM_SUCCESS){
			g_error("Can not initiate pam, dying");
		}

		ret = pam_authenticate(pamh, 0);    /* is user really user? */
		/* check auth */
		if (ret != PAM_SUCCESS){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_AUTH))
				g_warning("Bad password for user \"%s\"",user);
			pam_end(pamh,PAM_DATA_SILENT);
			return SASL_BADAUTH;
		}
		pam_end(pamh,PAM_DATA_SILENT);
	}


	ret = getpwnam_r(user, &result_buf, buffer, 512, &result_bufp);
	if (ret || (! result_bufp)){
		return SASL_BADAUTH;
	}

	*groups = getugroups(user,result_bufp->pw_gid);
	*userid = result_bufp->pw_uid;

	return SASL_OK;
}
