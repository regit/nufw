
/*
 ** Copyright(C) 2003-2006 INL
 **     written by Eric Leblond <eric@regit.org>
 **                Vincent Deffontaines <vincent@gryzor.com>
 **
 ** $Id$
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
#define LDAP_DEPRECATED 1

#include <auth_srv.h>
#include <auth_ldap.h>
#include "security.h"

/**
 * \ingroup NuauthModules
 * \defgroup AuthNuauthModules Authentication and acls checking modules
 *
 * \brief These type modules permit user authentication and acl checking
 *
 * It can export :
 *  - an user check function named user_check() function which realise user authentication.
 *  - an acl checking function named acl_check() function to get the acls matching a packet.
 *
 * \par
 * A special case is the ip authentication mechanism which require the export of function called ip_authentication().
 * It is used to authenticate people based on a method which does not involve a NuFW client. For the moment, only an ident
 * module is available.
 */

/*--- Decimal string <-> Base 10^n number type config --*/
typedef unsigned long digit_t;
#define BASE 1000000	 /** Use 6 decimal digits in each number digit */
#define BASE_LOG10 6
#define BASE2STR "%06lu"
#define DIGIT_COUNT 7	 /** BASE ^ DIGIT_COUNT should be able to store 2 ^ 128 */
#define INIT_NUMBER {0, 0, 0, 0, 0, 0, 0}
#if ULONG_MAX < (BASE*256)
#  error "Base is too big"
#endif
typedef digit_t number_t[DIGIT_COUNT];

/**
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


/**
 *
 * \ingroup AuthNuauthModules
 * \defgroup LdapModule LDAP authentication and acl module
 *
 * @{ */

/**
 * Multiply a "Base 10^n" number by a factor
 */
void number_multiply(number_t number, digit_t factor)
{
	unsigned char index;
	digit_t value = 0;
	for (index = 0; index < DIGIT_COUNT; index++) {
		value += (number[index] * factor);
		number[index] = value % BASE;
		value /= BASE;
	}
}

/**
 *
 * \file ldap.c
 * \brief Contains all LDAP modules functions
 */

/**
 * Add a value to a "Base 10^n" number
 *
 * \return Returns 0 on error, 1 otherwise
 */
int number_add(number_t number, digit_t value)
{
	unsigned char index = 0;
	for (; value != 0; index++) {
		value += number[index];
		number[index] = value % BASE;
		value /= BASE;
		if (index == DIGIT_COUNT) {
			return 0;
		}
	}
	return 1;
}

/**
 * Convert a "Base 10^n" number to decimal string.
 *
 * \return Returns new allocated string
 */
char *number_to_decimal(number_t number)
{
	char ascii[DIGIT_COUNT * BASE_LOG10 + 1];
	char *text;
	signed char index;
	for (index = DIGIT_COUNT - 1; 0 <= index; index--) {
		sprintf(ascii + (DIGIT_COUNT - index - 1) * BASE_LOG10,
			BASE2STR, number[index]);
	}
	text = ascii;
	while (text[0] == '0')
		text++;
	return strdup(text);
}

/**
 * Convert a decimal string to a "Base 10^n" number.
 *
 * \return Returns 0 on error, 1 otherwise
 */
int decimal_to_number(const char *orig_decimal, number_t number)
{
	ssize_t decimal_len = strlen(orig_decimal);
	char *decimal = strdup(orig_decimal);
	char *err;
	unsigned char index;
	for (index = 0; index < DIGIT_COUNT; index++)
		number[index] = 0;
	index = 0;
	while (BASE_LOG10 < decimal_len) {
		decimal[decimal_len] = 0;
		decimal_len -= BASE_LOG10;
		number[index] = strtol(decimal + decimal_len, &err, 10);
		index++;
		if (err == NULL || *err != 0 || DIGIT_COUNT <= index) {
			free(decimal);
			return 0;
		}
	}
	decimal[decimal_len] = 0;
	number[index] = strtol(decimal, &err, 10);
	free(decimal);
	if (err == NULL || *err != 0)
		return 0;
	else
		return 1;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	struct ldap_params *params = (struct ldap_params *) params_p;
	if (params) {
		g_free(params->binddn);
		g_free(params->bindpasswd);
		g_free(params->ldap_server);
		g_free(params->ldap_acls_base_dn);
		g_free(params->ldap_users_base_dn);
	}
	g_free(params);
	return TRUE;
}

/**
 * Init ldap system.
 */
G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	char *configfile = NULL;
	gpointer vpointer;
	struct ldap_params *params = g_new0(struct ldap_params, 1);
	char *ldap_base_dn = LDAP_BASE;
	confparams ldap_nuauth_vars[] = {
		{"ldap_server_addr", G_TOKEN_STRING, 0,
		 g_strdup(LDAP_SERVER)},
		{"ldap_server_port", G_TOKEN_INT, LDAP_SERVER_PORT, NULL},
		{"ldap_base_dn", G_TOKEN_STRING, 0, g_strdup(LDAP_BASE)},
		{"ldap_users_base_dn", G_TOKEN_STRING, 0,
		 g_strdup(LDAP_BASE)},
		{"ldap_acls_base_dn", G_TOKEN_STRING, 0,
		 g_strdup(LDAP_BASE)},
		{"ldap_bind_dn", G_TOKEN_STRING, 0, g_strdup(LDAP_USER)},
		{"ldap_bind_password", G_TOKEN_STRING, 0,
		 g_strdup(LDAP_CRED)},
		{"ldap_request_timeout", G_TOKEN_INT, LDAP_REQUEST_TIMEOUT,
		 NULL},
		{"ldap_filter_type", G_TOKEN_INT, 1, NULL}
	};


	log_message(VERBOSE_DEBUG, AREA_MAIN,
		    "Ldap module ($Revision$)");
	if (!module->configfile) {
		configfile = DEFAULT_CONF_FILE;
	} else {
		configfile = module->configfile;
	}


	/* parse conf file */
	parse_conffile(configfile,
		       sizeof(ldap_nuauth_vars) / sizeof(confparams),
		       ldap_nuauth_vars);
	/* set variables */
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_server_addr");
	params->ldap_server =
	    (char *) (vpointer ? vpointer : params->ldap_server);
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_server_port");
	params->ldap_server_port =
	    *(int *) (vpointer ? vpointer : &params->ldap_server_port);
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_bind_dn");
	params->binddn = (char *) (vpointer ? vpointer : params->binddn);
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_base_dn");
	ldap_base_dn = (char *) (vpointer ? vpointer : ldap_base_dn);
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_users_base_dn");
	params->ldap_users_base_dn =
	    (char *) (vpointer ? vpointer : params->ldap_users_base_dn);
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_acls_base_dn");
	params->ldap_acls_base_dn =
	    (char *) (vpointer ? vpointer : params->ldap_acls_base_dn);

	if (!strcmp(params->ldap_acls_base_dn, LDAP_BASE)) {
		params->ldap_acls_base_dn = ldap_base_dn;
	}
	if (!strcmp(params->ldap_users_base_dn, LDAP_BASE)) {
		params->ldap_users_base_dn = ldap_base_dn;
	}

	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_bind_password");
	params->bindpasswd =
	    (char *) (vpointer ? vpointer : params->bindpasswd);
	params->ldap_request_timeout = LDAP_REQUEST_TIMEOUT;
	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_request_timeout");
	params->ldap_request_timeout =
	    *(int *) (vpointer ? vpointer : &params->ldap_request_timeout);

	vpointer =
	    get_confvar_value(ldap_nuauth_vars,
			      sizeof(ldap_nuauth_vars) /
			      sizeof(confparams), "ldap_filter_type");
	params->ldap_filter_type =
	    *(int *) (vpointer ? vpointer : &params->ldap_filter_type);

	/* free config struct */
	free_confparams(ldap_nuauth_vars,
			sizeof(ldap_nuauth_vars) / sizeof(confparams));


	/* init thread private stuff */
	params->ldap_priv = g_private_new((GDestroyNotify) ldap_unbind);

	module->params = params;

	return TRUE;
}

/**
 * unload function.
 */
G_MODULE_EXPORT gchar *g_module_unload(void)
{
	return NULL;
}

/**
 * Initialize connection to ldap server.
 */

static LDAP *ldap_conn_init(struct ldap_params *params)
{
	LDAP *ld = NULL;
	int err, version = 3;

	/* init connection */
	ld = ldap_init(params->ldap_server, params->ldap_server_port);
	if (!ld) {
		log_message(WARNING, AREA_MAIN, "ldap init error\n");
		return NULL;
	}
	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
			    &version) == LDAP_OPT_SUCCESS) {
		/* Goes to ssl if needed */
#ifdef LDAP_OPT_X_TLS
		if (params->ldap_server_port == LDAPS_PORT) {
			int tls_option;
			tls_option = LDAP_OPT_X_TLS_TRY;
			ldap_set_option(ld, LDAP_OPT_X_TLS,
					(void *) &tls_option);
		}
#endif				/* LDAP_OPT_X_TLS */
		err =
		    ldap_bind_s(ld, params->binddn, params->bindpasswd,
				LDAP_AUTH_SIMPLE);
		if (err != LDAP_SUCCESS) {
			if (err == LDAP_SERVER_DOWN) {
				/* we lost connection, so disable current one */
				ldap_unbind(ld);
				ld = NULL;
				g_private_set(params->ldap_priv, ld);
				return NULL;
			}
			log_message(SERIOUS_WARNING, AREA_AUTH,
				    "ldap bind error : %s \n",
				    ldap_err2string(err));
			return NULL;
		}
	}
	return ld;
}

static char *ipv6_to_base10(struct in6_addr *addr)
{
	number_t number = INIT_NUMBER;
	unsigned char index = 0;

	for (index = 0; index < 16; index++) {
		if (number_add(number, addr->s6_addr[index]) != 1)
			return NULL;
		number_multiply(number, 256);
	}

	return number_to_decimal(number);
}


/**
 * \brief Escape character to protect them in query
 *
 * \verbatim
Abstract from RFC 2254
   Character       ASCII value
   ---------------------------
    *               0x2a
    (               0x28
    )               0x29
    \               0x5c
    NUL             0x00
For example * is coded \2a
\endverbatim
 *
 * \param basestring the string to convert
 * \return a newly allocated string
 */

gchar *escape_string_for_ldap(const gchar * basestring)
{
	int length = strlen(basestring) + 1;
	gchar *result = g_new0(gchar, length);
	const gchar *c_char = basestring;
	int i = 0;

	while (*c_char) {
		switch (*c_char) {
		case '*':
			length += 2;
			result = g_realloc(result, length);
			g_strlcat(result, "\\2a", length);
			i += 3;
			break;
		case '(':
			length += 2;
			result = g_realloc(result, length);
			g_strlcat(result, "\\28", length);
			i += 3;
			break;
		case ')':
			length += 2;
			result = g_realloc(result, length);
			g_strlcat(result, "\\29", length);
			i += 3;
			break;
		case '\\':
			length += 2;
			result = g_realloc(result, length);
			g_strlcat(result, "\\5c", length);
			i += 3;
			break;
		default:
			result[i] = *c_char;
			i++;
		}
		c_char++;
	}
	result[length - 1] = 0;
	return result;
}

/**
 * \brief Acl check function
 *
 * This function realise the matching of a packet against the set of rules. It is exported
 * by the modules and called by nuauth core.
 *
 * \param element A pointer to a ::connection_t which contains all informations available about the packet
 * \param params_p A pointer to the parameters of the module instance we're working for
 * \return A chained list of struct ::acl_group which is the set of acl that match the given packet
 *
 * The returned GSList has to be ordered because take_decision() will do a interative loop on the chained list. This
 * can be used to achieve complicated setup.
 */
G_MODULE_EXPORT GSList *acl_check(connection_t * element,
				  gpointer params_p)
{
	GSList *g_list = NULL;
	char filter[LDAP_QUERY_SIZE];
	char **attrs_array, **walker;
	int attrs_array_len, i, group;
	struct timeval timeout;
	struct acl_group *this_acl;
	LDAPMessage *res, *result;
	int err;
	struct ldap_params *params = (struct ldap_params *) params_p;
	LDAP *ld = g_private_get(params->ldap_priv);
	gchar *ip_src;
	gchar *ip_dst;
	gchar *prov_string;

	if (ld == NULL) {
		/* init ldap has never been done */
		ld = ldap_conn_init(params);
		if (ld == NULL) {
			log_message(SERIOUS_WARNING, AREA_AUTH,
				    "Can not initiate LDAP conn\n");
			return NULL;
		}
		g_private_set(params->ldap_priv, ld);
	}

	ip_src = ipv6_to_base10(&element->tracking.saddr);
	ip_dst = ipv6_to_base10(&element->tracking.daddr);
	if (ip_src == NULL || ip_dst == NULL) {
		free(ip_src);
		free(ip_dst);
		return NULL;
	}

	/* contruct filter */
	if ((element->tracking).protocol == IPPROTO_TCP
	    || (element->tracking).protocol == IPPROTO_UDP) {
		switch (params->ldap_filter_type) {
		case 1:
			if (snprintf(filter, LDAP_QUERY_SIZE - 1,
#if USE_SOURCE_PORT
				     "(&(objectClass=NuAccessControlList)(Proto=%d)(DstPort=%d)(SrcIPStart<=%s)(SrcIPEnd>=%s)(DstIPStart<=%s)(DstIPEnd>=%s)(SrcPortStart<=%d)(SrcPortEnd>=%d)",
#endif
				     "(&(objectClass=NuAccessControlList)(Proto=%d)(DstPort=%d)(SrcIPStart<=%s)(SrcIPEnd>=%s)(DstIPStart<=%s)(DstIPEnd>=%s)",
				     (element->tracking).protocol,
				     (element->tracking).dest,
				     ip_src, ip_src, ip_dst, ip_dst
#if USE_SOURCE_PORT
				     , (element->tracking).source,
				     (element->tracking).source
#endif
			    ) >= (LDAP_QUERY_SIZE - 1)) {
				log_message(WARNING, AREA_MAIN,
					    "LDAP query too big (more than %d bytes)\n",
					    LDAP_QUERY_SIZE);
				free(ip_src);
				free(ip_dst);
				return NULL;
			}
			break;
		case 0:
			if (snprintf(filter, LDAP_QUERY_SIZE - 1,
#if USE_SOURCE_PORT
				     "(&(objectClass=NuAccessControlList)(SrcIPStart<=%s)(SrcIPEnd>=%s)(DstIPStart<=%s)(DstIPEnd>=%s)(Proto=%d)(SrcPortStart<=%d)(SrcPortEnd>=%d)(DstPortStart<=%d)(DstPortEnd>=%d)",
#endif
				     "(&(objectClass=NuAccessControlList)(SrcIPStart<=%s)(SrcIPEnd>=%s)(DstIPStart<=%s)(DstIPEnd>=%s)(Proto=%d)(DstPortStart<=%d)(DstPortEnd>=%d)",
				     ip_src,
				     ip_src,
				     ip_dst,
				     ip_dst, (element->tracking).protocol,
#if USE_SOURCE_PORT
				     (element->tracking).source,
				     (element->tracking).source,
#endif
				     (element->tracking).dest,
				     (element->tracking).dest) >=
			    (LDAP_QUERY_SIZE - 1)) {
				log_message(WARNING, AREA_MAIN,
					    "LDAP query too big (more than %d bytes)\n",
					    LDAP_QUERY_SIZE);
				free(ip_src);
				free(ip_dst);
				return NULL;
			}
		}
		free(ip_src);
		free(ip_dst);

		/* finish filter */
		if (element->os_sysname) {
			g_strlcat(filter, "(|(&(OsName=*)(OsName=",
				  LDAP_QUERY_SIZE);
			prov_string =
			    escape_string_for_ldap(element->os_sysname);
			g_strlcat(filter, prov_string, LDAP_QUERY_SIZE);
			g_free(prov_string);
			g_strlcat(filter, "))(!(OsName=*)))",
				  LDAP_QUERY_SIZE);
		} else {
			g_strlcat(filter, "(!(OsName=*))",
				  LDAP_QUERY_SIZE);
		}
		if (element->app_name) {
			g_strlcat(filter, "(|(&(AppName=*)(AppName=",
				  LDAP_QUERY_SIZE);
			prov_string =
			    escape_string_for_ldap(element->app_name);
			g_strlcat(filter, prov_string, LDAP_QUERY_SIZE);
			g_free(prov_string);
			g_strlcat(filter, "))(!(AppName=*)))",
				  LDAP_QUERY_SIZE);
		} else {
			g_strlcat(filter, "(!(AppName=*))",
				  LDAP_QUERY_SIZE);
		}
		if (element->os_release) {
			g_strlcat(filter, "(|(&(OsRelease=*)(OsRelease=",
				  LDAP_QUERY_SIZE);
			prov_string =
			    escape_string_for_ldap(element->os_release);
			g_strlcat(filter, prov_string, LDAP_QUERY_SIZE);
			g_free(prov_string);
			g_strlcat(filter, "))(!(OsRelease=*)))",
				  LDAP_QUERY_SIZE);
		} else {
			g_strlcat(filter, "(!(OsRelease=*))",
				  LDAP_QUERY_SIZE);
		}
		if (element->os_version) {
			g_strlcat(filter, "(|(&(OsVersion=*)(OsVersion=",
				  LDAP_QUERY_SIZE);
			prov_string =
			    escape_string_for_ldap(element->os_version);
			g_strlcat(filter, prov_string, LDAP_QUERY_SIZE);
			g_free(prov_string);
			g_strlcat(filter, "))(!(OsVersion=*)))",
				  LDAP_QUERY_SIZE);
		} else {
			g_strlcat(filter, "(!(OsVersion=*))",
				  LDAP_QUERY_SIZE);
		}
		if (element->app_md5) {
			g_strlcat(filter, "(|(&(AppSig=*)(AppSig=",
				  LDAP_QUERY_SIZE);
			prov_string =
			    escape_string_for_ldap(element->app_md5);
			g_strlcat(filter, prov_string, LDAP_QUERY_SIZE);
			g_free(prov_string);
			g_strlcat(filter, "))(!(AppSig=*)))",
				  LDAP_QUERY_SIZE);
		} else {
			g_strlcat(filter, "(!(AppSig=*))",
				  LDAP_QUERY_SIZE);
		}


		g_strlcat(filter, ")", LDAP_QUERY_SIZE);
		debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
				  "LDAP filter : \n%s\n", filter);

	} else if ((element->tracking).protocol == IPPROTO_ICMP) {
		if (snprintf(filter, LDAP_QUERY_SIZE - 1,
			     "(&(objectClass=NuAccessControlList)"
			     "(SrcIPStart<=%s)(SrcIPEnd>=%s)"
			     "(DstIPStart<=%s)(DstIPEnd>=%s)"
			     "(Proto=%d)"
			     "(SrcPortStart<=%d)(SrcPortEnd>=%d)"
			     "(DstPortStart<=%d)(DstPortEnd>=%d))",
			     ip_src, ip_src,
			     ip_dst, ip_dst,
			     (element->tracking).protocol,
			     (element->tracking).type,
			     (element->tracking).type,
			     (element->tracking).code,
			     (element->tracking).code) >=
		    (LDAP_QUERY_SIZE - 1)) {
			log_message(WARNING, AREA_MAIN,
				    "LDAP query too big (more than %d bytes)\n",
				    LDAP_QUERY_SIZE);
			free(ip_src);
			free(ip_dst);
			return NULL;
		}
		free(ip_src);
		free(ip_dst);
	}

	/* send query and wait result */
	timeout.tv_sec = params->ldap_request_timeout;
	timeout.tv_usec = 0;
#ifdef PERF_DISPLAY_ENABLE
	{
		struct timeval tvstart, tvend, result;
		gettimeofday(&tvstart, NULL);
#endif

		err =
		    ldap_search_st(ld, params->ldap_acls_base_dn,
				   LDAP_SCOPE_SUBTREE, filter, NULL, 0,
				   &timeout, &res);

#ifdef PERF_DISPLAY_ENABLE
		gettimeofday(&tvend, NULL);
		timeval_substract(&result, &tvend, &tvstart);
		g_message("ldap query time : %ld.%06ld", result.tv_sec,
			  result.tv_usec);
	}
#endif
	if (err != LDAP_SUCCESS) {
		if (err == LDAP_SERVER_DOWN) {
			/* we lost connection, so disable current one */
			log_message(WARNING, AREA_MAIN,
				    "disabling current connection");
			ldap_unbind(ld);
			ld = NULL;
			g_private_set(params->ldap_priv, ld);
		}
		log_message(WARNING, AREA_MAIN,
			    "invalid return from ldap_search_st : %s\n",
			    ldap_err2string(err));
		return NULL;
	}
	/* parse result to feed a group_list */
	if (ldap_count_entries(ld, res) >= 1) {
		result = ldap_first_entry(ld, res);
		while (result) {
			/* get period */
			attrs_array =
			    ldap_get_values(ld, result, "TimeRange");
			if (attrs_array && *attrs_array) {
				this_acl->period = g_strdup(*attrs_array);
			}
			ldap_value_free(attrs_array);

			/* get description (log prefix) */
			attrs_array =
			    ldap_get_values(ld, result, "description");
			if (attrs_array && *attrs_array) {
				this_acl->log_prefix =
				    g_strdup(*attrs_array);
			}
			ldap_value_free(attrs_array);

			/* allocate a new acl_group */
			this_acl = g_new0(struct acl_group, 1);
			g_assert(this_acl);
			this_acl->groups = NULL;
			this_acl->period = NULL;
			this_acl->log_prefix = NULL;

			/* get decision */
			attrs_array =
			    ldap_get_values(ld, result, "Decision");
			sscanf(*attrs_array, "%d",
			       (int *) &(this_acl->answer));
			debug_log_message(DEBUG, AREA_AUTH,
					  "Acl found with decision %d (timerange: %s)\n",
					  this_acl->answer,
					  this_acl->period);
			ldap_value_free(attrs_array);
			/* build groups  list */
			attrs_array = ldap_get_values(ld, result, "Group");
			attrs_array_len = ldap_count_values(attrs_array);
			walker = attrs_array;
			for (i = 0; i < attrs_array_len; i++) {
				sscanf(*walker, "%d", &group);
				this_acl->groups =
				    g_slist_prepend(this_acl->groups,
						    GINT_TO_POINTER
						    (group));
				walker++;
			}
			ldap_value_free(attrs_array);
			result = ldap_next_entry(ld, result);
			/* add when acl is filled */
			if (this_acl->groups != NULL) {
				g_list = g_slist_prepend(g_list, this_acl);
			} else {
				g_free(this_acl);
			}
		}
		ldap_msgfree(res);
		return g_list;
	} else {

		debug_log_message(DEBUG, AREA_AUTH, "No acl found\n");
		ldap_msgfree(res);
	}
	return NULL;
}

/* @} */
