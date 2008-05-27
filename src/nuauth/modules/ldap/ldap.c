/*
 ** Copyright(C) 2003-2008 INL
 **     written by Eric Leblond <eric@inl.fr>
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

#include <auth_srv.h>
#include <auth_ldap.h>
#include "security.h"
#include "nubase.h"

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

#define LDAP_MAX_TRY 2

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
	char *decimal = g_strdup(orig_decimal);
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
			g_free(decimal);
			return 0;
		}
	}
	decimal[decimal_len] = 0;
	number[index] = strtol(decimal, &err, 10);
	g_free(decimal);
	if (err == NULL || *err != 0)
		return 0;
	else
		return 1;
}


static void ldap_conn_destroy(void * connection)
{
	if (connection) {
		ldap_unbind_ext_s(connection, NULL, NULL);
	}
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
	struct ldap_params *params = g_new0(struct ldap_params, 1);
	char *ldap_base_dn = LDAP_BASE;

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Ldap module ($Revision$)");

	/* set variables */
	params->ldap_server = nubase_config_table_get_or_default("ldap_server_addr", LDAP_SERVER);
	params->ldap_server_port = nubase_config_table_get_or_default_int("ldap_server_port", LDAP_SERVER_PORT);
	params->binddn = nubase_config_table_get_or_default("ldap_bind_dn",LDAP_USER);
	ldap_base_dn = nubase_config_table_get_or_default("ldap_base_dn",LDAP_BASE);
	params->ldap_users_base_dn = nubase_config_table_get_or_default("ldap_users_base_dn",LDAP_BASE);
	params->ldap_acls_base_dn = nubase_config_table_get_or_default("ldap_acls_base_dn",LDAP_BASE);
	if (!strcmp(params->ldap_acls_base_dn, LDAP_BASE)) {
		params->ldap_acls_base_dn = ldap_base_dn;
	}
	if (!strcmp(params->ldap_users_base_dn, LDAP_BASE)) {
		params->ldap_users_base_dn = ldap_base_dn;
	}
	params->bindpasswd = nubase_config_table_get_or_default("ldap_bind_password",LDAP_CRED);
	params->ldap_request_timeout = nubase_config_table_get_or_default_int("ldap_request_timeout",LDAP_REQUEST_TIMEOUT);
	params->ldap_use_ipv4_schema = nubase_config_table_get_or_default_int("ldap_use_ipv4_schema", 1);
	params->ldap_filter_type = nubase_config_table_get_or_default_int("ldap_filter_type", 1);


	/* init thread private stuff */
	params->ldap_priv = g_private_new((GDestroyNotify) ldap_conn_destroy);

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
	char uri[1024];
	struct berval password;

	/* init connection */
	if ( ! secure_snprintf(uri, 1024, "%s://%s:%u",
		(params->ldap_server_port == LDAPS_PORT) ? "ldaps" : "ldap",
		params->ldap_server, params->ldap_server_port) ) {
		log_message(WARNING, DEBUG_AREA_MAIN, "LDAP: could not build URI");
		return NULL;
	}
	ldap_initialize(&ld, uri);
	if (!ld) {
		log_message(WARNING, DEBUG_AREA_MAIN, "Ldap init error");
		return NULL;
	}
	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
			    &version) == LDAP_OPT_SUCCESS) {
		/* Goes to ssl if needed */

#if 0
#ifdef LDAP_OPT_X_TLS
		if (params->ldap_server_port == LDAPS_PORT) {
			int tls_option;
			tls_option = LDAP_OPT_X_TLS_HARD;
			err = ldap_set_option(ld, LDAP_OPT_X_TLS,
					(void *) &tls_option);
			if (err != LDAP_OPT_SUCCESS) {
				log_message(SERIOUS_WARNING, DEBUG_AREA_AUTH,
					    "Can not set tls option: %s",
					    ldap_err2string(err));
				return NULL;
			}
		}
#endif /* LDAP_OPT_X_TLS */
#endif

		password.bv_val = params->bindpasswd;
		password.bv_len = strlen(password.bv_val);
		err = ldap_sasl_bind_s(ld, params->binddn, LDAP_SASL_SIMPLE,
				&password, NULL, NULL, NULL);
		if (err != LDAP_SUCCESS) {
			if (err == LDAP_SERVER_DOWN) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "Can not connect to ldap: %s",
					    ldap_err2string(err));
				/* we lost connection, so disable current one */
				ldap_unbind_ext_s(ld, NULL, NULL);
				ld = NULL;
				g_private_set(params->ldap_priv, ld);
				return NULL;
			}
			log_message(SERIOUS_WARNING, DEBUG_AREA_AUTH,
				    "Ldap bind error : %s",
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

struct weighted_acl {
	struct acl_group *acl;
	int weight;
};

gint compare_acl_weight(gconstpointer data1, gconstpointer data2)
{
	return ((struct weighted_acl *)data2)->weight
		- ((struct weighted_acl *)data1)->weight;
}

static void local_free(gpointer data, gpointer userdata)
{
	g_free(data);
}

/**
 * \return A nu_error_t::, NU_EXIT_CONTINUE if filter did not match, NU_EXIT_OK if filter did match.
 */

static nu_error_t field_match_pattern(gchar * value, LDAP *ld, LDAPMessage *result, gchar *attribute)
{
	nu_error_t ret = NU_EXIT_CONTINUE;
	struct berval **attrs_array;
	struct berval **pattrs_array;

	attrs_array = ldap_get_values_len(ld, result, attribute);
	if (attrs_array && *attrs_array) {
		pattrs_array = attrs_array;
		while (*pattrs_array) {
			if (g_pattern_match_simple(
						(*pattrs_array)->bv_val,
						value
						)) {
				ret = NU_EXIT_OK;
				break;
			}
			pattrs_array++;
		}
	} else {
		/* No attributes in LDAP, thus criteria filtering is a success */
		ret = NU_EXIT_OK;
	}
	ldap_value_free_len(attrs_array);
	return ret;
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
	GSList *g_acl_list = NULL;
	GSList *temp_list = NULL;
	char filter[LDAP_QUERY_SIZE];
	struct berval **attrs_array, **walker;
	int attrs_array_len, i, integer;
	struct timeval timeout;
	struct acl_group *this_acl;
	struct weighted_acl *this = NULL;
	LDAPMessage *res, *result;
	int ok, err, try;
	struct ldap_params *params = (struct ldap_params *) params_p;
	LDAP *ld = g_private_get(params->ldap_priv);
	gchar *ip_src;
	gchar *ip_dst;
	gchar *prov_string;

	if (params->ldap_use_ipv4_schema) {
		struct in_addr ipv4;
		if (!is_ipv4(&element->tracking.saddr) ||
				!is_ipv4(&element->tracking.daddr)) {
			log_message(SERIOUS_WARNING, DEBUG_AREA_AUTH,
				    "ldap: IPv4 schema but IPv6 address\n");
			return NULL;
		}
		ipv6_to_ipv4(&element->tracking.saddr, &ipv4);
		ip_src = g_strdup_printf("%u", ipv4.s_addr);
		ipv6_to_ipv4(&element->tracking.daddr, &ipv4);
		ip_dst = g_strdup_printf("%u", ipv4.s_addr);
	} else {
		ip_src = ipv6_to_base10(&element->tracking.saddr);
		ip_dst = ipv6_to_base10(&element->tracking.daddr);
	}
	if (ip_src == NULL || ip_dst == NULL) {
		g_free(ip_src);
		g_free(ip_dst);
		return NULL;
	}

	/* contruct filter */
	if ((element->tracking).protocol == IPPROTO_TCP
	    || (element->tracking).protocol == IPPROTO_UDP) {
		switch (params->ldap_filter_type) {
		case 1:
			ok = secure_snprintf(filter, sizeof(filter),
				"(&(objectClass=NuAccessControlList)"
				"(Proto=%d)"
				"(DstPort=%d)"
				"(SrcIPStart<=%s)(SrcIPEnd>=%s)"
				"(DstIPStart<=%s)(DstIPEnd>=%s)",
				element->tracking.protocol,
				element->tracking.dest,
				ip_src, ip_src,
				ip_dst, ip_dst);
			if (!ok) {
				log_message(WARNING, DEBUG_AREA_MAIN,
					    "LDAP query too big (more than %d bytes)\n",
					    LDAP_QUERY_SIZE);
				g_free(ip_src);
				g_free(ip_dst);
				return NULL;
			}
			break;
		case 0:
			ok = secure_snprintf(filter, sizeof(filter),
				"(&(objectClass=NuAccessControlList)"
				"(SrcIPStart<=%s)(SrcIPEnd>=%s)"
				"(DstIPStart<=%s)(DstIPEnd>=%s)"
				"(Proto=%d)"
				"(DstPortStart<=%d)(DstPortEnd>=%d)",
				ip_src, ip_src,
				ip_dst,	ip_dst,
				element->tracking.protocol,
				element->tracking.dest, element->tracking.dest);
			if (!ok) {
				log_message(WARNING, DEBUG_AREA_MAIN,
					    "LDAP query too big (more than %d bytes)\n",
					    LDAP_QUERY_SIZE);
				g_free(ip_src);
				g_free(ip_dst);
				return NULL;
			}
		}
		g_free(ip_src);
		g_free(ip_dst);

		/* finish filter */
		if (! element->os_sysname) {
			g_strlcat(filter, "(!(OsName=*))", LDAP_QUERY_SIZE);
		}
		if (! element->os_release) {
			g_strlcat(filter, "(!(OsRelease=*))", LDAP_QUERY_SIZE);
		}
		if (! element->os_version) {
			g_strlcat(filter, "(!(OsVersion=*))", LDAP_QUERY_SIZE);
		}
		if (! element->app_name) {
			g_strlcat(filter, "(!(AppName=*))", LDAP_QUERY_SIZE);
		}

		g_strlcat(filter, ")", LDAP_QUERY_SIZE);
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				  "LDAP filter : \n%s\n", filter);

	} else if ((element->tracking).protocol == IPPROTO_ICMP) {
		ok = secure_snprintf(filter, sizeof(filter),
			"(&(objectClass=NuAccessControlList)"
			"(SrcIPStart<=%s)(SrcIPEnd>=%s)"
			"(DstIPStart<=%s)(DstIPEnd>=%s)"
			"(Proto=%d)"
			"(SrcPortStart<=%d)(SrcPortEnd>=%d)"
			"(DstPortStart<=%d)(DstPortEnd>=%d))",
			ip_src, ip_src,
			ip_dst, ip_dst,
			element->tracking.protocol,
			element->tracking.type,
			element->tracking.type,
			element->tracking.code,
			element->tracking.code);
		if (!ok) {
			log_message(WARNING, DEBUG_AREA_MAIN,
				    "LDAP query too big (more than %d bytes)\n",
				    LDAP_QUERY_SIZE);
			g_free(ip_src);
			g_free(ip_dst);
			return NULL;
		}
		g_free(ip_src);
		g_free(ip_dst);
	}

	try = 0;
	do {
		try++;
		if (ld == NULL) {
			/* init ldap has never been done */
			ld = ldap_conn_init(params);
			if (ld == NULL) {
				log_message(SERIOUS_WARNING, DEBUG_AREA_AUTH,
						"Can not initiate LDAP conn\n");
				return NULL;
			}
			g_private_set(params->ldap_priv, ld);
		}

		/* send query and wait result */
		timeout.tv_sec = params->ldap_request_timeout;
		timeout.tv_usec = 0;
#ifdef PERF_DISPLAY_ENABLE
		{
			struct timeval tvstart, tvend, result;
			if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
				gettimeofday(&tvstart, NULL);
			}
#endif

			err = ldap_search_ext_s(ld, params->ldap_acls_base_dn,
						LDAP_SCOPE_SUBTREE, filter, NULL, 0,
						NULL, NULL,
						&timeout, LDAP_NO_LIMIT, &res);

#ifdef PERF_DISPLAY_ENABLE
			if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
				gettimeofday(&tvend, NULL);
				timeval_substract(&result, &tvend, &tvstart);
				log_message(INFO, DEBUG_AREA_PERF, "Ldap query time: %.1f msec",
						(double)result.tv_sec*1000+(double)(result.tv_usec/1000));
			}
		}
#endif
		if (err != LDAP_SUCCESS) {
			if (err == LDAP_SERVER_DOWN) {
				/* we lost connection, so disable current one */
				log_message(WARNING, DEBUG_AREA_MAIN,
						"disabling current connection");
				ldap_unbind_ext_s(ld, NULL, NULL);
				ld = NULL;
				g_private_set(params->ldap_priv, ld);
			} else {
				break;
			}
		}
	} while ((err != LDAP_SUCCESS) || (try < LDAP_MAX_TRY));

	if ((try == LDAP_MAX_TRY) && (err != LDAP_SUCCESS)) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "invalid return from ldap_search_st : %s\n",
			    ldap_err2string(err));
		return NULL;
	}
	/* parse result to feed a group_list */
	if (ldap_count_entries(ld, res) >= 1) {
		for(result=ldap_first_entry(ld, res); result; result=ldap_next_entry(ld, result)) {
			gboolean break_loop = FALSE;

#define TEST_PATTERN(x, y) switch (field_match_pattern(element->x, ld, result, y)) { \
				case NU_EXIT_OK: \
					break; \
				case NU_EXIT_CONTINUE: \
					/* this is not a match, going to test next acl */ \
					break_loop = TRUE; \
					break; \
				case NU_EXIT_ERROR: \
					log_message(WARNING, DEBUG_AREA_MAIN, \
						    "Invalid return from field_match_pattern"); \
					return NULL; \
				default: \
					log_message(WARNING, DEBUG_AREA_MAIN, \
						    "Impossible return from field_match_pattern"); \
					return NULL; \
					break; \
			} \
			if (break_loop) { \
				continue; \
			}

			TEST_PATTERN(app_name, "AppName");
			TEST_PATTERN(os_sysname, "OsName");
			TEST_PATTERN(os_release, "OsRelease");
			TEST_PATTERN(os_version, "OsVersion");

#undef TEST_PATTERN

			/* allocate a new acl_group */
			this_acl = g_new0(struct acl_group, 1);
			if (nuauthconf->prio_to_nok == 2) {
				this = g_new0(struct weighted_acl, 1);
			}
			g_assert(this_acl);
			this_acl->users = NULL;
			this_acl->groups = NULL;
			this_acl->period = NULL;
			this_acl->log_prefix = NULL;
			this_acl->flags = ACL_FLAGS_NONE;

			/* get period */
			attrs_array = ldap_get_values_len(ld, result, "TimeRange");
			if (attrs_array && *attrs_array) {
				this_acl->period = g_strdup((*attrs_array)->bv_val);
			}
			ldap_value_free_len(attrs_array);

			/* get description (log prefix) */
			attrs_array = ldap_get_values_len(ld, result, "description");
			if (attrs_array && *attrs_array) {
				this_acl->log_prefix = g_strdup((*attrs_array)->bv_val);
			}
			ldap_value_free_len(attrs_array);

			/* get flags */
			attrs_array = ldap_get_values_len(ld, result, "AclFlags");
			if (attrs_array && *attrs_array) {
				sscanf((*attrs_array)->bv_val, "%d", (int *) &(this_acl->flags));
			}
			ldap_value_free_len(attrs_array);

			if (nuauthconf->prio_to_nok == 2) {
				/* get weight */
				attrs_array = ldap_get_values_len(ld, result, "AclWeight");
				if (attrs_array && *attrs_array) {
					sscanf((*attrs_array)->bv_val, "%d", (int *) &(this->weight));
				} else {
					this->weight = 0;
				}
				ldap_value_free_len(attrs_array);
			}

			/* get decision */
			attrs_array = ldap_get_values_len(ld, result, "Decision");
			sscanf((*attrs_array)->bv_val, "%d", (int *) &(this_acl->answer));
			debug_log_message(DEBUG, DEBUG_AREA_AUTH,
					  "Acl found with decision %d (timerange: %s)\n",
					  this_acl->answer,
					  this_acl->period);
			ldap_value_free_len(attrs_array);
			/* build groups list */
			attrs_array = ldap_get_values_len(ld, result, "Group");
			attrs_array_len = ldap_count_values_len(attrs_array);
			walker = attrs_array;
			for (i = 0; i < attrs_array_len; i++) {
				sscanf((*walker)->bv_val, "%d", &integer);
				this_acl->groups =
				    g_slist_prepend(this_acl->groups,
						    GINT_TO_POINTER
						    (integer));
				walker++;
			}
			ldap_value_free_len(attrs_array);
			/* build users  list */
			attrs_array = ldap_get_values_len(ld, result, "User");
			attrs_array_len = ldap_count_values_len(attrs_array);
			walker = attrs_array;
			for (i = 0; i < attrs_array_len; i++) {
				sscanf((*walker)->bv_val, "%d", &integer);
				this_acl->users =
				    g_slist_prepend(this_acl->users,
						    GINT_TO_POINTER
						    (integer));
				walker++;
			}
			ldap_value_free_len(attrs_array);

			if (nuauthconf->prio_to_nok == 2) {
				this->acl = this_acl;
			}

			/* add when acl is filled */
			if (this_acl->groups || this_acl->users) {
				if (nuauthconf->prio_to_nok == 2) {
					g_list = g_slist_insert_sorted(g_list,
							this,
							compare_acl_weight);
				} else {
					g_list = g_slist_prepend(g_list, this_acl);
				}
			} else {
				g_free(this_acl);
				if (nuauthconf->prio_to_nok == 2) {
					g_free(this);
				}
			}
		}
		ldap_msgfree(res);

		if (nuauthconf->prio_to_nok == 2) {
			for (temp_list = g_list; temp_list;
			     temp_list = temp_list->next) {
				g_acl_list = g_slist_append(
						g_acl_list,
						((struct weighted_acl *)temp_list->data)->acl
						);
			}
			g_slist_foreach(g_list, local_free, NULL);
			g_slist_free(g_list);
			return g_acl_list;
		} else {
			return g_list;
		}
	} else {
		debug_log_message(DEBUG, DEBUG_AREA_AUTH, "No acl found\n");
		ldap_msgfree(res);
	}
	return NULL;
}

/* @} */



