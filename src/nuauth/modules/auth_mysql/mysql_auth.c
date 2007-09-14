/*
 ** Copyright(C) 2003-2007 Wi-Next
 ** Written by Francesco Varano	- <francesco.varano@winext.eu>
 **	       Gabriele Messineo- <gabriele.messineo@winext.eu>
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
/* code inspired from log_mysql & plaintext */

#include "mysql_auth.h"

#define IP_AUTH_IPAUTH_GUEST_USERNAME "guest"
#define IP_AUTH_IPAUTH_GUEST_USERID 0
#define IP_AUTH_IPAUTH_GUEST_GROUPID 97

/* MySQL schema
 *
 * create table userinfo(uid int primary key auto_increment,username varchar(256));
 * create table groups(gid int primary key auto_increment,groupname varchar(256));
 * create table groupinfo(uid int, gid int,PRIMARY KEY(uid,gid));
 *
 */

/** Minimum buffer size to write an IPv6 in SQL syntax */
#define IPV6_SQL_STRLEN (2+16*2+1)

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

static MYSQL *mysql_conn_init(struct ipauth_mysql_params *params);
static MYSQL *get_mysql_handler(struct ipauth_mysql_params *params);
static int ipv6_to_sql(struct ipauth_mysql_params *params, struct in6_addr *addr,
	char *buffer, size_t buflen, int use_ntohl);
static void free_ipauth_user(gpointer);
static nu_error_t mysql_close_current(struct ipauth_mysql_params* params);

/**
 *
 * \ingroup LoggingNuauthModules
 * \defgroup MySQLAuthentication MySQL authentication module
 *
 * @{ */

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	struct ipauth_params *params = (struct ipauth_params *) params_p;
	struct ipauth_mysql_params *mysql = params->mysql;

	if (mysql) {
		g_free(mysql->mysql_user);
		g_free(mysql->mysql_passwd);
		g_free(mysql->mysql_server);
		g_free(mysql->mysql_db_name);
		g_free(mysql->mysql_ipauth_table_name);
		g_free(mysql->mysql_userinfo_table_name);
		g_free(mysql->mysql_groups_table_name);
		g_free(mysql->mysql_groupinfo_table_name);
		g_free(mysql->mysql_ssl_keyfile);
		g_free(mysql->mysql_ssl_certfile);
		g_free(mysql->mysql_ssl_ca);
		g_free(mysql->mysql_ssl_capath);
		g_free(mysql->mysql_ssl_cipher);
		g_free(mysql);
	}

	if (params->users)
		g_hash_table_remove_all(params->users);

	params->mysql = NULL;
	params->users = NULL;

	return TRUE;
}

/* Init mysql system */
G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	confparams_t mysql_nuauth_vars[] = {
		{"mysql_server_addr", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_SERVER)}
		,
		{"mysql_server_port", G_TOKEN_INT, MYSQL_SERVER_PORT, NULL}
		,
		{"mysql_user", G_TOKEN_STRING, 0, g_strdup(MYSQL_USER)}
		,
		{"mysql_passwd", G_TOKEN_STRING, 0, g_strdup(MYSQL_PASSWD)}
		,
		{"mysql_db_name", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_DB_NAME)}
		,
		{"mysql_ipauth_table_name", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_IPAUTH_TABLE_NAME)}
		,
		{"mysql_userinfo_table_name", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_USERINFO_TABLE_NAME)}
		,
		{"mysql_groups_table_name", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_GROUPS_TABLE_NAME)}
		,
		{"mysql_groupinfo_table_name", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_GROUPINFO_TABLE_NAME)}
		,
		{"mysql_request_timeout", G_TOKEN_INT,
		 MYSQL_REQUEST_TIMEOUT, NULL}
		,
		{"mysql_use_ipv4_schema", G_TOKEN_INT,
		 MYSQL_USE_IPV4_SCHEMA, NULL}
		,
		{"mysql_use_ssl", G_TOKEN_INT, MYSQL_USE_SSL, NULL}
		,
		{"mysql_ssl_keyfile", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_SSL_KEYFILE)}
		,
		{"mysql_ssl_certfile", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_SSL_CERTFILE)}
		,
		{"mysql_ssl_ca", G_TOKEN_STRING, 0, g_strdup(MYSQL_SSL_CA)}
		,
		{"mysql_ssl_capath", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_SSL_CAPATH)}
		,
		{"mysql_ssl_cipher", G_TOKEN_STRING, 0,
		 g_strdup(MYSQL_SSL_CIPHER)}
	};
	char *configfile = DEFAULT_CONF_FILE;
	/* char *ldap_base_dn=LDAP_BASE; */
	struct ipauth_params *ipauth =
	    g_new0(struct ipauth_params, 1);
	struct ipauth_mysql_params *mysql =
	    g_new0(struct ipauth_mysql_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "IPAUTH MySQL module Revision: "IPAUTH_REV);
	/* init global variables */
	mysql->mysql_ssl_cipher = MYSQL_SSL_CIPHER;
	/* mysql->hook = module->hook; */

	/* parse conf file */
	if (module->configfile) {
		parse_conffile(module->configfile,
			       sizeof(mysql_nuauth_vars) /
			       sizeof(confparams_t), mysql_nuauth_vars);
	} else {
		parse_conffile(configfile,
			       sizeof(mysql_nuauth_vars) /
			       sizeof(confparams_t), mysql_nuauth_vars);
	}
	/* set variables */

#define READ_CONF(KEY) \
    get_confvar_value(mysql_nuauth_vars, sizeof(mysql_nuauth_vars)/sizeof(confparams_t), KEY)
#define READ_CONF_INT(VAR, KEY, DEFAULT) \
    do { gpointer vpointer = READ_CONF(KEY); if (vpointer) VAR = *(int *)vpointer; else VAR = DEFAULT; } while (0)

	mysql->mysql_server = (char *) READ_CONF("mysql_server_addr");
	mysql->mysql_user = (char *) READ_CONF("mysql_user");
	mysql->mysql_passwd = (char *) READ_CONF("mysql_passwd");
	mysql->mysql_db_name = (char *) READ_CONF("mysql_db_name");
	/* ipauth specific tables */
	mysql->mysql_ipauth_table_name = (char *) READ_CONF("mysql_ipauth_table_name");
	mysql->mysql_userinfo_table_name = (char *) READ_CONF("mysql_userinfo_table_name");
	mysql->mysql_groups_table_name = (char *) READ_CONF("mysql_groups_table_name");
	mysql->mysql_groupinfo_table_name = (char *) READ_CONF("mysql_groupinfo_table_name");
	/* endof ipauth specific tables */
	mysql->mysql_ssl_keyfile = (char *) READ_CONF("mysql_ssl_keyfile");
	mysql->mysql_ssl_certfile = (char *) READ_CONF("mysql_ssl_certfile");
	mysql->mysql_ssl_ca = (char *) READ_CONF("mysql_ssl_ca");
	mysql->mysql_ssl_capath = (char *) READ_CONF("mysql_ssl_capath");
	mysql->mysql_ssl_cipher = (char *) READ_CONF("mysql_ssl_cipher");

	READ_CONF_INT(mysql->mysql_server_port, "mysql_server_port",
		      MYSQL_SERVER_PORT);
	READ_CONF_INT(mysql->mysql_request_timeout,
		      "mysql_request_timeout", MYSQL_REQUEST_TIMEOUT);
	READ_CONF_INT(mysql->mysql_use_ssl, "mysql_use_ssl",
		      MYSQL_USE_SSL);
	READ_CONF_INT(mysql->mysql_use_ipv4_schema,
		      "mysql_use_ipv4_schema", MYSQL_USE_IPV4_SCHEMA);

	/* free config struct */
	free_confparams(mysql_nuauth_vars,
			sizeof(mysql_nuauth_vars) / sizeof(confparams_t));

	/* init thread private stuff */
	mysql->mysql_priv = g_private_new(NULL);
	log_message(DEBUG, DEBUG_AREA_MAIN,
		    "mysql part of the config file is parsed");

	ipauth->users = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_ipauth_user);
	ipauth->mysql = mysql;
	module->params = (gpointer) ipauth;

	return TRUE;
}

/*
 * Initialize connection to mysql server
 */
static MYSQL *mysql_conn_init(struct ipauth_mysql_params *params)
{
	MYSQL *ld = NULL;
#ifdef MYSQL_OPT_RECONNECT
	my_bool trueval = 1;
#endif

	/* init connection */
	ld = mysql_init(ld);
	if (ld == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN, "mysql init error : %s",
			    strerror(errno));
		return NULL;
	}
#if HAVE_MYSQL_SSL
	/* Set SSL options, if configured to do so */
	if (params->mysql_use_ssl)
		mysql_ssl_set(ld, params->mysql_ssl_keyfile,
			      params->mysql_ssl_certfile,
			      params->mysql_ssl_ca,
			      params->mysql_ssl_capath,
			      params->mysql_ssl_cipher);
#endif
#if 0
	/* Set MYSQL object properties */
	if (mysql_options(ld, MYSQL_OPT_CONNECT_TIMEOUT, mysql_conninfo) !=
	    0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "mysql options setting failed : %s",
			    mysql_error(ld));
	}
#endif
#ifdef MYSQL_OPT_RECONNECT
#  if defined(MYSQL_VERSION_ID) && (MYSQL_VERSION_ID >= 50019)
	mysql_options(ld, MYSQL_OPT_RECONNECT, &trueval);
#  endif
#endif
	if (!mysql_real_connect
	    (ld, params->mysql_server, params->mysql_user,
	     params->mysql_passwd, params->mysql_db_name,
	     params->mysql_server_port, NULL, 0)) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "mysql connection failed : %s",
			    mysql_error(ld));
		mysql_close(ld);
		return NULL;
	}
#ifdef MYSQL_OPT_RECONNECT
#  if defined(MYSQL_VERSION_ID) && (MYSQL_VERSION_ID < 50019)
	mysql_options(ld, MYSQL_OPT_RECONNECT, &trueval);
#  endif
#endif
	ipauth_mysql_conn_list = g_slist_prepend(ipauth_mysql_conn_list, ld);

	return ld;
}

static char *quote_string(MYSQL * mysql, const char *text)
{
	unsigned int length = strlen(text);
	char *quoted;
	if (length == 0)
		return strdup(text);
	quoted = (char *) malloc(length * 2 + 1);
	if (mysql_real_escape_string(mysql, quoted, text, length) == 0) {
		g_free(quoted);
		return NULL;
	}
	return quoted;
}

#define SELECT_FIELDS "username"
/**
 *  * @{ */

G_MODULE_EXPORT gchar* ip_authentication(tracking_t * header, struct ipauth_params* params)
{
	char request[LONG_REQUEST_SIZE];
	char ip_ascii[IPV6_SQL_STRLEN];
	/* char ip_ascii[40]; */
	MYSQL *ld;
	gboolean ok;
	MYSQL_ROW row;
	char *username = NULL;
	/* u_int32_t saddr=htonl(header->saddr); */ /*!< IPv4 source address */

	if (ipv6_to_sql(params->mysql, &header->saddr, ip_ascii, sizeof(ip_ascii), 1) != 0)
		return NULL;

	ld = get_mysql_handler(params->mysql);
	if (ld == NULL) {
		return NULL;
	}

	if (params->mysql->mysql_use_ipv4_schema) {
		ok = secure_snprintf(request, sizeof(request),
			"SELECT " SELECT_FIELDS
			" FROM  %s "
			"WHERE ip_saddr = (%s & netmask) AND"
			"(end_time is NULL OR "
			"end_time > NOW())",
			params->mysql->mysql_ipauth_table_name,
			ip_ascii);
	} else {
		ok = secure_snprintf(request, sizeof(request),
			"SELECT " SELECT_FIELDS
			" FROM  %s "
			"WHERE check_net(ip_saddr, %s, netmask) AND "
			"(end_time is NULL OR "
			"end_time > NOW())",
			params->mysql->mysql_ipauth_table_name,
			ip_ascii);
	}
	if (!ok) {
		log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
		"[IPAUTH MySQL] cannot create query: %s", request);
		return NULL;
	}

	/* execute query */
	if ( (ok = mysql_real_query(ld, request, strlen(request))) ) {
		log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
			"[IPAUTH MySQL] Cannot execute request: %s",
			mysql_error(ld));
		mysql_close_current(params->mysql);
		return NULL;
	} else {
		MYSQL_RES *result = mysql_store_result(ld);
		if ( (row = mysql_fetch_row(result) ))
			username = g_strdup(row[0]);
		mysql_free_result(result);
	}

	return username ? username : g_strdup(IP_AUTH_IPAUTH_GUEST_USERNAME);
}

/**
 *  user_check()
 *
 *  \param username user name string
 *  \param clientpass user provided password
 *  \param passlen password length
 *  \param params module related parameter
 *  \return SASL_OK if password is correct, other values are authentication
 *           failures
 */
G_MODULE_EXPORT int user_check(const char *username,
			       const char *clientpass, unsigned passlen,
			       struct ipauth_params* params)
{
	struct ipauth_mysql_params *mysql = params->mysql;
	MYSQL *ld = NULL;
	char request[LONG_REQUEST_SIZE];
	int ret;
	char *quoted_username = NULL;
	char *quoted_clientpass = NULL;

	if(!(ld = get_mysql_handler(mysql)))
		return SASL_BADAUTH;

	quoted_username = quote_string(ld, username);
	if (! quoted_username)
		return SASL_BADAUTH;

	quoted_clientpass = quote_string(ld, clientpass);
	if (! quoted_clientpass)
		return SASL_BADAUTH;

	if(!secure_snprintf(request, sizeof(request),
					"SELECT uid FROM %s WHERE username='%s' AND "
					"password=PASSWORD('%s')",
					mysql->mysql_userinfo_table_name,
					quoted_username,
					quoted_clientpass)) {
		g_free(quoted_username);
		g_free(quoted_clientpass);
		return SASL_BADAUTH;
	}

	g_free(quoted_username);
	g_free(quoted_clientpass);

	/* execute query */
	if ( mysql_real_query(ld, request, strlen(request)) ) {
		log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
				"[IPAUTH MySQL] Cannot execute request: %s",
				mysql_error(ld));
		mysql_close_current(params->mysql);
		return SASL_BADAUTH;
	} else {
		MYSQL_RES *result = mysql_store_result(ld);
		if (mysql_affected_rows(ld))
			ret = SASL_OK;
		else
			ret = SASL_BADAUTH;

		mysql_free_result(result);
	}

	return ret;
}

G_MODULE_EXPORT uint32_t get_user_id(const char *username, struct ipauth_params* params)
{
	struct ipauth_mysql_params *mysql = params->mysql;
	MYSQL *ld = NULL;
	char request[LONG_REQUEST_SIZE];
	int ok;
	uid_t uid = IP_AUTH_IPAUTH_GUEST_USERID;
	MYSQL_ROW row;
	char *endptr=NULL;
	struct ipauth_user *user;
	char *quoted_username = NULL;

	if ( (user=g_hash_table_lookup(params->users, username)) ) {
		/* log_message(INFO, DEBUG_AREA_AUTH, */
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				"[IPAUTH MySQL:get_user_id] found user in hash table");
		return user->uid;
	}
	/* log_message(INFO, DEBUG_AREA_AUTH, */
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		  	"[IPAUTH MySQL:get_user_id] searching user in mysql table");

	if(!(ld = get_mysql_handler(mysql)))
		return NU_EXIT_ERROR;

	quoted_username = quote_string(ld, username);
	if (! quoted_username)
		return NU_EXIT_ERROR;

	if(!(ok = secure_snprintf(request, sizeof(request),
					"SELECT uid FROM %s WHERE username='%s'",
					mysql->mysql_userinfo_table_name, 
					quoted_username))) {
		g_free(quoted_username);
		return NU_EXIT_ERROR;
	}

	/* execute query */
	if ( (ok = mysql_real_query(ld, request, strlen(request))) ) {
		log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
				"[IPAUTH MySQL] Cannot execute request: %s",
				mysql_error(ld));
		mysql_close_current(params->mysql);
		return NU_EXIT_ERROR;
	} else {
		MYSQL_RES *result = mysql_store_result(ld);
		if ((ok=mysql_affected_rows(ld))==1) {
			if ( (row = mysql_fetch_row(result) )) {
				uid=strtol(row[0],&endptr,10);
				if(*endptr)
					uid = NU_EXIT_ERROR;
				else {
					user=g_new0(struct ipauth_user, 1);
					user->username = g_strdup(username);
					user->uid = uid;
					g_hash_table_insert(params->users, user->username, user);
				}
			}
		} else if (ok > 1)
			uid = NU_EXIT_ERROR;
		mysql_free_result(result);
	}

	return uid;
}

G_MODULE_EXPORT GSList *get_user_groups(const char *username, struct ipauth_params* params)
{
	struct ipauth_mysql_params *mysql = params->mysql;
	MYSQL *ld = NULL;
	char request[LONG_REQUEST_SIZE];
	/* int mysql_ret; */
	int ok;
	MYSQL_ROW row;
	GSList *grouplist = NULL;
	gid_t gid;
	int ng=0;
	char *endptr=NULL;
	struct ipauth_user *user;
	int64_t uid = -1;

	if ( (user=g_hash_table_lookup(params->users, username)) && user->groups ) {
		/* log_message(INFO, DEBUG_AREA_AUTH, */
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				"[IPAUTH MySQL:get_user_groups] found user in hash table");
		return g_slist_copy(user->groups);
	}
	/* log_message(INFO, DEBUG_AREA_AUTH, */
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		  	"[IPAUTH MySQL:get_user_groups] searching user in mysql table");

	if(!(ld = get_mysql_handler(mysql)))
		return NULL;

	if(!(ok = secure_snprintf(request, sizeof(request),
			"SELECT gid,%s.uid FROM %s JOIN %s ON %s.uid=%s.uid WHERE username='%s'",
			mysql->mysql_userinfo_table_name, mysql->mysql_groupinfo_table_name,
			mysql->mysql_userinfo_table_name, mysql->mysql_groupinfo_table_name,
			mysql->mysql_userinfo_table_name, username)) )
					/* "SELECT gid,users.uid FROM groupinfo JOIN users ON groupinfo.uid=users.uid WHERE username='%s'", username)) ) */
					/* "SELECT groupinfo.gid,users.uid FROM groupinfo,users WHERE groupinfo.uid=users.uid and users.username='%s'",username)) )  */
					/* "SELECT gid FROM groupinfo WHERE uid IN (SELECT uid FROM users where username='%s')",username)) )  */
		return NULL;

	/* execute query */
	if ( (ok = mysql_real_query(ld, request, strlen(request)))) {
		log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
				"[IPAUTH MySQL] Cannot execute request: %s",
				mysql_error(ld));
		mysql_close_current(params->mysql);
		return NULL;
	} else {
		MYSQL_RES *result = mysql_store_result(ld);
		if((ng=mysql_affected_rows(ld))<1)
			grouplist = g_slist_prepend(grouplist,
				GINT_TO_POINTER(IP_AUTH_IPAUTH_GUEST_GROUPID));
		else {
			for(ok=0;ok<ng && (row = mysql_fetch_row(result) );ok++) {
				gid=strtol(row[0],&endptr,10);
				if(*endptr) {
					log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
						"[IPAUTH MySQL] error getting Group ID: %s", row[0]);
					continue;
				}
				grouplist = g_slist_prepend(grouplist, GINT_TO_POINTER(gid));
				if (uid<0) {
					uid=strtol(row[1],&endptr,10);
					if(*endptr) {
						log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
							"[IPAUTH MySQL] error getting User ID: %s",
							row[1]);
						continue;
					}
				}

			}
		}
		mysql_free_result(result);
	}
	/* store user to cache */
	if (!user) {
		user=g_new0(struct ipauth_user, 1);
		user->username = g_strdup(username);
		user->uid = uid;
		g_hash_table_insert(params->users, user->username, user);
	}
	user->groups = grouplist;

	return g_slist_copy(user->groups);

}

/* ------------------------------------------------------------------------------------- */
/* --------------------------- STATIC FUNCTIONS ---------------------------------------- */
/* ------------------------------------------------------------------------------------- */

static MYSQL *get_mysql_handler(struct ipauth_mysql_params *params)
{
	MYSQL *ld = g_private_get(params->mysql_priv);

	if (ld)
		return ld;

	ld = mysql_conn_init(params);
	if (ld == NULL) {
		log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
			    "Can not initiate MYSQL connection");
		return NULL;
	}
	g_private_set(params->mysql_priv, ld);
	return ld;

}

const gchar *g_module_check_init(GModule *module)
{
	ipauth_mysql_conn_list = NULL;

	mysql_server_init(0, NULL, NULL);
	return NULL;
}

void g_module_unload(GModule *module)
{
	GSList* pointer = ipauth_mysql_conn_list;

	if (ipauth_mysql_conn_list) {
		while (pointer) {
			mysql_close((MYSQL *)pointer->data);
			pointer=pointer->next;
		}
		g_slist_free(ipauth_mysql_conn_list);
	}

	ipauth_mysql_conn_list = NULL;

	/* mysql_server_end(); */
}

/**
 * Convert an IPv6 address to SQL binary string.
 * Eg. ::1 => "0x0000000000000001"
 *
 * \return Returns -1 if fails, 0 otherwise.
 */
static int ipv6_to_sql(
	struct ipauth_mysql_params *params,
	struct in6_addr *addr,
	char *buffer,
	size_t buflen,
	int use_ntohl)
{
	unsigned char i;
	unsigned char *addr8;
	size_t written;

	if (!params->mysql_use_ipv4_schema) {
		/* format IPv6 to BINARY(16) as "0x..." */
		if (buflen < IPV6_SQL_STRLEN) {
			buffer[0] = 0;
			return -1;
		}
		buffer[0] = '0';
		buffer[1] = 'x';
		buffer += 2;
		addr8 = &addr->s6_addr[0];
		for (i = 0; i < 4; i++) {
			written = sprintf(buffer, "%02x%02x%02x%02x",
					addr8[0], addr8[1], addr8[2], addr8[3]);
			if (written != 2 * 4) {
				buffer[0] = 0;
				return -1;
			}
			buffer += written;
			addr8 += 4;
		}
		buffer[0] = 0;
	} else {
		int ok;
		uint32_t ip;
		/* format IPv6 to "a.b.c.d" but only for IPv4 in IPv6 */
		if (!is_ipv4(addr)) {
			log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
				    "MySQL: Packet has IPV6 address but MySQL use IPV4 only schema");
			return -1;
		}
		ip = addr->s6_addr32[3];
		if (use_ntohl)
			ip = ntohl(ip);
		ok = secure_snprintf(buffer, buflen, "%u", ip);

		if (!ok) return -1;
	}
	return 0;
}

static void free_ipauth_user(gpointer user)
{
	if (user) {
		g_free(((struct ipauth_user *)user)->username);
		g_slist_free(((struct ipauth_user *)user)->groups);
	}
}

static nu_error_t mysql_close_current(struct ipauth_mysql_params* params)
{
	MYSQL* ld = get_mysql_handler(params);
	if (ld) {
		mysql_close(ld);
	}
	g_private_set(params->mysql_priv, NULL);
	return NU_EXIT_OK;
}

/** @} */
