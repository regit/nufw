/*
 ** Copyright(C) 2006 INL
 **	written by Victor Stinner <victor.stinner AT haypocalc.com>
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

#include "log_prelude.h"
#include <prelude.h>
#include <prelude-log.h>
#include <idmef-tree-wrap.h>

/**
 *
 * \ingroup LoggingNuauthModules
 * \defgroup PreludeModule Prelude logging module
 *
 * @{ */


#define NUFW_ANALYZER_MANUFACTURER "http://www.nufw.org/"
#define NUFW_ANALYZER_CLASS "Firewall"
#define NUFW_ANALYZER_VERSION NUAUTH_FULL_VERSION
#define NUFW_ANALYZER_MODEL "NuFW"

#define CLIENT_ANALYZER_NAME "libnuclient"
#define CLIENT_ANALYZER_MANUFACTURER NUFW_ANALYZER_MANUFACTURER
#define CLIENT_ANALYZER_CLASS "NuFW client"
#define CLIENT_ANALYZER_MODEL "NuFW"

GMutex *global_client_mutex;
prelude_client_t *global_client;	/* private pointer for prelude client connection */

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


G_MODULE_EXPORT gchar *unload_module_with_params(gpointer params_ptr)
{
	return NULL;
}

/**
 * Function called every second to update timer (Prelude "heartbeat")
 */
void update_prelude_timer()
{
	prelude_timer_wake_up();
}

/**
 * Function called only once: when the module is unloaded.
 *
 * \return NULL
 */
G_MODULE_EXPORT void g_module_unload(GModule * module)
{
	log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
		    "[+] Prelude log: Close client connection");
	prelude_client_destroy(global_client,
			       PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
	g_mutex_free(global_client_mutex);

	cleanup_func_remove(update_prelude_timer);

	log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
		    "[+] Prelude log: Deinit library");
	prelude_deinit();
}

/**
 * Destroy a private IDMEF message when a thread stops.
 */
void destroy_idmef(idmef_message_t * idmef)
{
	idmef_message_destroy(idmef);
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct log_prelude_params *params =
	    g_new0(struct log_prelude_params, 1);


	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Log_nuprelude module ($Revision$)");

	params->packet_tpl = g_private_new((GDestroyNotify) destroy_idmef);
	params->session_tpl = g_private_new((GDestroyNotify) destroy_idmef);
	module->params = (gpointer) params;
	return TRUE;
}

/**
 * Delete an IDMEF object
 */
static void del_idmef_object(idmef_message_t * message, const char *object)
{
	idmef_value_t *val;
	idmef_path_t *path;
	if (idmef_path_new(&path, object) < 0) {
		return;
	}
	if (0 < idmef_path_get(path, message, &val)) {
		idmef_value_destroy(val);
	}
	idmef_path_destroy(path);
	return;
}

/**
 * Add an IDMEF object
 */
static int add_idmef_object(idmef_message_t * message, const char *object,
			    const char *value)
{
	int ret;
	idmef_value_t *val, *oldval;
	idmef_path_t *path;


	ret = idmef_path_new(&path, object);
	if (ret < 0) {
		log_message(DEBUG, DEBUG_AREA_MAIN,
			    "Prelude: Fail to set attribute %s=%s: %s",
			    object, value, prelude_strerror(ret));
		return -1;
	}

	/* remove old value if it does exist */
	ret = idmef_path_get(path, message, &oldval);
	if (0 < ret) {
		idmef_value_destroy(oldval);
	}

	/* set new value */
	ret = idmef_value_new_from_path(&val, path, value);
	if (ret < 0) {
		log_message(DEBUG, DEBUG_AREA_MAIN,
			    "Prelude: Fail to set attribute %s=%s: %s",
			    object, value, prelude_strerror(ret));
		idmef_path_destroy(path);
		return -1;
	}
	ret = idmef_path_set(path, message, val);
	idmef_value_destroy(val);
	idmef_path_destroy(path);
	return ret;
}

/**
 * Set default values in an IDMEF template
 */
static int feed_template(idmef_message_t * idmef)
{
	idmef_analyzer_t *client_analyzer, *analyzer;
	idmef_alert_t *alert;
	prelude_string_t *string;
	int ret;

	/* set assessment */
	add_idmef_object(idmef, "alert.assessment.impact.type", "user");

	/* create analyzer */
	alert = idmef_message_get_alert(idmef);
	if (!alert) {
		return 0;
	}
#if 0
	ret = idmef_alert_new_analyzer(alert, &analyzer, 1);
	if (ret < 0)
		return 0;
#else
	client_analyzer = prelude_client_get_analyzer(global_client);
	ret = idmef_analyzer_clone(client_analyzer, &analyzer);
	if (ret < 0)
		return 0;
	idmef_alert_set_analyzer(alert, analyzer, 1); /*IDMEF_LIST_APPEND */
#endif

	/* configure analyzer */
	ret = idmef_analyzer_new_model(analyzer, &string);
	if (ret < 0)
		return 0;
	prelude_string_set_constant(string, NUFW_ANALYZER_MODEL);

	ret = idmef_analyzer_new_class(analyzer, &string);
	if (ret < 0)
		return 0;
	prelude_string_set_constant(string, NUFW_ANALYZER_CLASS);

	ret = idmef_analyzer_new_version(analyzer, &string);
	if (ret < 0)
		return 0;
	prelude_string_set_constant(string, NUFW_ANALYZER_VERSION);

	ret = idmef_analyzer_new_manufacturer(analyzer, &string);
	if (ret < 0)
		return 0;
	prelude_string_set_constant(string, NUFW_ANALYZER_MANUFACTURER);
	return 1;
}

/**
 * Create Prelude alert message template.
 *
 * \return NULL on error, or new allocated idmef message on succes.
 */
static idmef_message_t *create_alert_template()
{
	idmef_message_t *idmef;
	int ret;

	ret = idmef_message_new(&idmef);
	if (ret < 0) {
		prelude_perror(ret, "unable to create IDMEF message");
		return NULL;
	}

	ret = feed_template(idmef);
	if (!ret) {
		prelude_perror(ret, "unable to create IDMEF message");
		idmef_message_destroy(idmef);
		return NULL;
	}
	return idmef;
}

/**
 * Create Prelude packet message template
 *
 * \return NULL on error, or new allocated idmef message on succes.
 */
static idmef_message_t *create_packet_template()
{
	idmef_message_t *idmef = create_alert_template();
	if (!idmef)
		return NULL;
	return idmef;
}

/**
 * Set libnuclient as IDMEF source #0: protocol version and service name
 */
static void feed_source_libnuclient(idmef_message_t *idmef)
{
	add_idmef_object(idmef,
			 "alert.source(0).service.iana_protocol_number",
			 "6");
	add_idmef_object(idmef, "alert.source(0).service.protocol", "tcp");
	add_idmef_object(idmef, "alert.source(0).service.name",
			 "nufw-client");
}

/**
 * Set nuauth as IDMEF target #0: process path and pid, source IPv6, protocol
 */
static void feed_target_nuauth(idmef_message_t *idmef)
{
	char buffer[50];
	char *process_name;

	add_idmef_object(idmef, "alert.target(0).process.path",
		nuauthdatas->program_fullpath);
	process_name = g_path_get_basename(nuauthdatas->program_fullpath);
	add_idmef_object(idmef, "alert.target(0).process.name",
		process_name);
	g_free(process_name);

	secure_snprintf(buffer, sizeof(buffer), "%lu", (unsigned long) getpid());
	add_idmef_object(idmef, "alert.target(0).process.pid", buffer);
	add_idmef_object(idmef, "alert.target(0).service.port", nuauthconf->userpckt_port);
	add_idmef_object(idmef, "alert.target(0).service.protocol", "tcp");
}

/**
 * Create Prelude authentication error message template
 *
 * \return NULL on error, or new allocated idmef message on succes.
 */
static idmef_message_t *create_autherr_template()
{
	idmef_message_t *idmef = create_alert_template();
	if (!idmef)
		return NULL;

	feed_source_libnuclient(idmef);
	feed_target_nuauth(idmef);

	return idmef;
}

/**
 * Create Prelude session message template
 *
 * \return NULL on error, or new allocated idmef message on succes.
 */
static idmef_message_t *create_session_template()
{
	idmef_message_t *idmef = create_alert_template();
	if (!idmef)
		return NULL;

	feed_source_libnuclient(idmef);
	feed_target_nuauth(idmef);

	return idmef;
}

/**
 * Create an IDMEF message from a template and set common parameters
 */
idmef_message_t* create_from_template(idmef_message_t *tpl, connection_t *conn)
{
	idmef_message_t *idmef;
	idmef_alert_t *alert;
	idmef_time_t *create_time;
	idmef_time_t *detect_time;
	time_t now;
	int ret;
	time_t *creation_timestamp;

	/* copy the message */
	if (idmef_message_clone(tpl, &idmef) < 0) {
		return NULL;
	}

	now = time(NULL);

	ret = idmef_message_new_alert(idmef, &alert);
	if (ret < 0) {
		idmef_message_destroy(idmef);
		return 0;
	}

	/* set create time */
	if (conn) {
		creation_timestamp = &conn->timestamp;
	} else {
		creation_timestamp = &now;
	}
	ret = idmef_time_new_from_time(&create_time, creation_timestamp);
	if (ret < 0) {
		idmef_message_destroy(idmef);
		return 0;
	}
	idmef_alert_set_create_time(alert, create_time);

	/* set detect time */
	ret = idmef_alert_new_detect_time(alert, &detect_time);
	if (ret < 0) {
		idmef_message_destroy(idmef);
		return 0;
	}
	idmef_time_set_from_time(detect_time, &now);
	return idmef;
}

/**
 * Set operating system informations of a IDMEF message:
 *  - create an analyzer to store libnuclient informations
 *  - set name, model, class, manufacturer
 *  - set OS type and version
 */
void set_os_infos(idmef_message_t *idmef, char* osname, char *osrelease, char *osversion)
{
	idmef_alert_t *alert;
	idmef_analyzer_t *analyzer;
	prelude_string_t *string = NULL;
	gchar* fullversion;
	int ret;

	alert = idmef_message_get_alert(idmef);
	if (!alert)
		return;

	ret = idmef_alert_new_analyzer(alert, &analyzer, 2);
	if (ret < 0)
		return;


	/* configure analyzer */
	ret = idmef_analyzer_new_name(analyzer, &string);
	if (ret < 0)
		return;
	prelude_string_set_constant(string, CLIENT_ANALYZER_NAME);

	ret = idmef_analyzer_new_model(analyzer, &string);
	if (ret < 0)
		return;
	prelude_string_set_constant(string, CLIENT_ANALYZER_MODEL);

	ret = idmef_analyzer_new_class(analyzer, &string);
	if (ret < 0)
		return;
	prelude_string_set_constant(string, CLIENT_ANALYZER_CLASS);

	ret = idmef_analyzer_new_manufacturer(analyzer, &string);
	if (ret < 0)
		return;
	prelude_string_set_constant(string, CLIENT_ANALYZER_MANUFACTURER);

	/* OS informations */
	ret = idmef_analyzer_new_ostype(analyzer, &string);
	if (ret < 0)
		return;
	prelude_string_set_dup(string, osname);

	fullversion = g_strdup_printf("%s %s", osrelease, osversion);
	ret = idmef_analyzer_new_osversion(analyzer, &string);
	if (ret < 0)
		return;
	if (fullversion) {
		prelude_string_set_dup(string, fullversion);
		g_free(fullversion);
	} else {
		prelude_string_set_dup(string, osversion);
	}
}

void set_source0_address(idmef_message_t *idmef, struct in6_addr *addr)
{
	char ip_ascii[INET6_ADDRSTRLEN];
	FORMAT_IPV6(addr, ip_ascii);
	add_idmef_object(idmef,
			 "alert.source(0).node.address(0).address",
			 ip_ascii);
}

/**
 * Create IDMEF message for NuFW packet message
 */
static idmef_message_t *create_message_packet(idmef_message_t * tpl,
					      tcp_state_t state,
					      connection_t * conn,
					      char *state_text,
					      char *impact, char *severity)
{
	idmef_message_t *idmef;
	char buffer[50];
	char ip_ascii[INET6_ADDRSTRLEN];
	char *tmp_buffer;
	unsigned short psrc, pdst;

	idmef = create_from_template(tpl, conn);
	if (!idmef) {
		return NULL;
	}

	if (state == TCP_STATE_DROP)
		tmp_buffer = "failed";
	else
		tmp_buffer = "succeeded";
	add_idmef_object(idmef, "alert.assessment.impact.completion", tmp_buffer);
	add_idmef_object(idmef, "alert.classification.text", state_text);
	add_idmef_object(idmef, "alert.assessment.impact.severity", severity);
	add_idmef_object(idmef, "alert.assessment.impact.description",
			 impact);

	/* IP source/dest */
	set_source0_address(idmef, &conn->tracking.saddr);
	FORMAT_IPV6(&conn->tracking.daddr, ip_ascii);
	add_idmef_object(idmef, "alert.target(0).node.address(0).address", ip_ascii);

	/* IP protocol */
	if (secure_snprintf
	    (buffer, sizeof(buffer), "%hu", conn->tracking.protocol)) {
		add_idmef_object(idmef,
				 "alert.source(0).service.iana_protocol_number",
				 buffer);
		add_idmef_object(idmef,
				 "alert.target(0).service.iana_protocol_number",
				 buffer);
	}

	/* TCP/UDP ports */
	if (conn->tracking.protocol == IPPROTO_TCP
	    || conn->tracking.protocol == IPPROTO_UDP) {
		if ((state ==
		     TCP_STATE_ESTABLISHED)
		    /* || (state == TCP_STATE_DROP) */ ) {
			psrc = conn->tracking.dest;
			pdst = conn->tracking.source;
		} else {
			psrc = conn->tracking.source;
			pdst = conn->tracking.dest;
		}
		if (secure_snprintf(buffer, sizeof(buffer), "%hu", psrc)) {
			add_idmef_object(idmef,
					 "alert.source(0).service.port",
					 buffer);
		}
		if (secure_snprintf(buffer, sizeof(buffer), "%hu", pdst)) {
			add_idmef_object(idmef,
					 "alert.target(0).service.port",
					 buffer);
		}
	} else {
		del_idmef_object(idmef, "alert.source(0).service.port");
		del_idmef_object(idmef, "alert.target(0).service.port");
		if (conn->tracking.protocol == IPPROTO_ICMP) {
			add_idmef_object(idmef,
					 "alert.source(0).service.name",
					 "icmp");
			add_idmef_object(idmef,
					 "alert.target(0).service.name",
					 "icmp");
		}
	}

	/* informations about nufw server */
	if (conn->tls) {
		add_idmef_object(idmef, "alert.source(1).process.name", "nufw");
		add_idmef_object(idmef, "alert.source(1).service.protocol", "tcp");
		add_idmef_object(idmef, "alert.source(1).service.port", nuauthconf->authreq_port);
		add_idmef_object(idmef, "alert.source(1).service.iana_protocol_number", "6");
		FORMAT_IPV6(&conn->tls->peername, ip_ascii);
		add_idmef_object(idmef, "alert.source(1).node.address(0).address", ip_ascii);
	}

	/* user informations */
	if (conn->username != NULL) {
		add_idmef_object(idmef,
				 "alert.source(0).user.user_id(0).type",
				 "current-user");
		add_idmef_object(idmef, "alert.source(0).user.category", "application");	/* os-device */
		add_idmef_object(idmef,
				 "alert.source(0).user.user_id(0).name",
				 conn->username);
		if (secure_snprintf
		    (buffer, sizeof(buffer), "%lu", conn->user_id)) {
			add_idmef_object(idmef,
					 "alert.source(0).user.user_id(0).number",
					 buffer);
		}
	} else {
		del_idmef_object(idmef, "alert.source(0).user");
	}

	/* source process */
	if (conn->app_name != NULL) {
		tmp_buffer = g_path_get_basename(conn->app_name);
		add_idmef_object(idmef, "alert.source(0).process.name",
				 tmp_buffer);
		g_free(tmp_buffer);
		add_idmef_object(idmef, "alert.source(0).process.path",
				 conn->app_name);
	} else {
		del_idmef_object(idmef, "alert.source(0).process");
	}

	/* os informations */
	if (conn->os_sysname != NULL) {
		set_os_infos(idmef, conn->os_sysname, conn->os_release, conn->os_version);
	}

	return idmef;
}

/**
 * Add NuFW client informations to an IDMEF message: user name and identifier
 */
static void add_user_information(idmef_message_t * idmef,
				 user_session_t * session,
				 int userid_is_valid)
{
	char buffer[50];
	if (session->user_name != NULL) {
		add_idmef_object(idmef,
				 "alert.source(0).user.user_id(0).type",
				 "current-user");
		add_idmef_object(idmef, "alert.source(0).user.category", "application");	/* os-device */
		add_idmef_object(idmef,
				 "alert.source(0).user.user_id(0).name",
				 session->user_name);
		if (userid_is_valid && secure_snprintf
		    (buffer, sizeof(buffer), "%lu", session->user_id)) {
			add_idmef_object(idmef,
					 "alert.source(0).user.user_id(0).number",
					 buffer);
		}
	} else {
		del_idmef_object(idmef, "alert.source(0).user");
	}
}

/**
 * Create IDMEF message for a NuFW session message
 */
static idmef_message_t *create_message_session(idmef_message_t * tpl,
					       user_session_t * session,
					       char *state_text,
					       char *impact,
					       char *severity)
{
	idmef_message_t *idmef;
	char buffer[50];
	char ip_ascii[INET6_ADDRSTRLEN];

	idmef = create_from_template(tpl, NULL);
	if (!idmef) {
		return NULL;
	}

	add_idmef_object(idmef, "alert.classification.text", state_text);
	add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded");
	add_idmef_object(idmef, "alert.assessment.impact.severity", severity);	/* info | low | medium | high */
	add_idmef_object(idmef, "alert.assessment.impact.description",
			 impact);

	/* source address/service */
	secure_snprintf(buffer, sizeof(buffer), "%hu", session->sport);
	add_idmef_object(idmef,	"alert.source(0).service.port", buffer);

	set_source0_address(idmef, &session->addr);

	/* set user informations */
	add_user_information(idmef, session, 1);

	FORMAT_IPV6(&session->server_addr, ip_ascii);
	add_idmef_object(idmef,
			"alert.target(0).node.address(0).address", ip_ascii);

	/* os informations */
	set_os_infos(idmef, session->sysname, session->release, session->version);
	return idmef;
}

static idmef_message_t *create_message_autherr(idmef_message_t * tpl,
					       user_session_t * session,
					       const char *text,
					       const char *severity)
{
	idmef_message_t *idmef;
	char buffer[50];
	char ip_ascii[INET6_ADDRSTRLEN];

	idmef = create_from_template(tpl, NULL);
	if (!idmef) {
		return NULL;
	}

	add_idmef_object(idmef, "alert.assessment.impact.completion", "failed");
	add_idmef_object(idmef, "alert.assessment.impact.severity",
			 severity);

	add_idmef_object(idmef, "alert.classification.text",
			 "Authentication error");
	add_idmef_object(idmef, "alert.assessment.impact.description",
			 text);

	/* source address */
	set_source0_address(idmef, &session->addr);

	secure_snprintf(buffer, sizeof(buffer), "%hu", session->sport);
	add_idmef_object(idmef,	"alert.source(0).service.port", buffer);

	FORMAT_IPV6(&session->server_addr, ip_ascii);
	add_idmef_object(idmef,
			"alert.target(0).node.address(0).address", ip_ascii);

	/* set user informations */
	add_user_information(idmef, session, 0);

	return idmef;
}

/** \todo Take into account connection_t* to void* change */
G_MODULE_EXPORT gint user_packet_logs(connection_t * element,
				      tcp_state_t state,
				      gpointer params_ptr)
{
	struct log_prelude_params *params = params_ptr;
	idmef_message_t *tpl;
	idmef_message_t *message;
	char *impact;
	char *state_text;
	char *severity;

	impact = "notify connection state change";
	switch (state) {
	case TCP_STATE_OPEN:
		state_text = "Open connection";
		severity = "low";
		break;
	case TCP_STATE_ESTABLISHED:
		state_text = "Connection established";
		severity = "info";
		break;
	case TCP_STATE_CLOSE:
		state_text = "Close connection";
		severity = "low";
		break;
	case TCP_STATE_DROP:
		if (element->username != NULL) {
			state_text = "Drop auth connection";
			severity = "high";
		} else {
			state_text =
			    "Drop unauth connection (auth timeout)";
			severity = "medium";
		}
		break;
	default:
		return -1;
	}

	/* get message template (or create it if needed) */
	tpl = g_private_get(params->packet_tpl);
	if (!tpl) {
		tpl = create_packet_template();
		if (!tpl)
			return -1;
		g_private_set(params->packet_tpl, tpl);
	}

	/* feed message fields */
	message =
	    create_message_packet(tpl, state, element, state_text, impact,
				  severity);
	if (!message) {
		return -1;
	}

	/* send message */
	g_mutex_lock(global_client_mutex);
	prelude_client_send_idmef(global_client, message);
	g_mutex_unlock(global_client_mutex);
	idmef_message_destroy(message);
	return 0;
}

G_MODULE_EXPORT int user_session_logs(user_session_t * c_session,
				      session_state_t state,
				      gpointer params_ptr)
{
	struct log_prelude_params *params = params_ptr;
	idmef_message_t *tpl;
	idmef_message_t *message;
	char *impact = NULL;
	char *severity;
	char *state_text;

	severity = "low";
	switch (state) {
	case SESSION_OPEN:
		state_text = "User log in";
		impact = g_strdup_printf("User \"%s\" log in", c_session->user_name);
		break;
	case SESSION_CLOSE:
		state_text = "User log out";
		impact = g_strdup_printf("User \"%s\" log out", c_session->user_name);
		break;
	default:
		return -1;
	}

	/* get message template (or create it if needed) */
	tpl = g_private_get(params->session_tpl);
	if (!tpl) {
		tpl = create_session_template();
		if (!tpl) {
			g_free(impact);
			return -1;
		}
		g_private_set(params->session_tpl, tpl);
	}

	/* feed message fields */
	message =
	    create_message_session(tpl, c_session, state_text, impact,
				   severity);
	g_free(impact);
	if (!message) {
		return -1;
	}

	/* send message */
	g_mutex_lock(global_client_mutex);
	prelude_client_send_idmef(global_client, message);
	g_mutex_unlock(global_client_mutex);
	idmef_message_destroy(message);
	return 0;
}

/**
 * Function called only once: when the module is loaded.
 *
 * \return NULL
 */
G_MODULE_EXPORT gchar *g_module_check_init()
{
	const char *version;
	int argc = 1;
	char *argv[2];
	int ret;
	argv[0] = nuauthdatas->program_fullpath;
	argv[1] = NULL;

	log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
		    "[+] Prelude log: Init Prelude library");

	version = prelude_check_version(PRELUDE_VERSION_REQUIRE);
	if (version == NULL) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Fatal error: Prelude module needs prelude version %s (installed version is %s)!",
			    PRELUDE_VERSION_REQUIRE,
			    prelude_check_version(NULL));
		exit(EXIT_FAILURE);
	}

	ret = prelude_init(&argc, argv);
	if (ret < 0) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Fatal error: Fail to init Prelude module: %s!",
			    prelude_strerror(ret));
		exit(EXIT_FAILURE);
	}


	log_message(SERIOUS_WARNING, DEBUG_AREA_MAIN,
		    "[+] Prelude log: Open client connection");

	/* Ask Prelude to don't log anything */
	prelude_log_set_flags(PRELUDE_LOG_FLAGS_QUIET);

	/* create a new client */
	global_client_mutex = g_mutex_new();
	ret = prelude_client_new(&global_client, "nufw");
	if (!global_client) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Fatal error: Unable to create a prelude client object: %s!",
			    prelude_strerror(ret));
		exit(EXIT_FAILURE);
	}

	ret = prelude_client_start(global_client);
	if (ret < 0) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Fatal error: Unable to start prelude client: %s!",
			    prelude_strerror(ret));
		exit(EXIT_FAILURE);
	}

	cleanup_func_push(update_prelude_timer);
	return NULL;
}

G_MODULE_EXPORT void auth_error_log(user_session_t * session,
				    nuauth_auth_error_t error,
				    const char *text, gpointer params_ptr)
{
	struct log_prelude_params *params = params_ptr;
	idmef_message_t *tpl;
	idmef_message_t *message;
	const char *severity;

	/* get message template (or create it if needed) */
	tpl = g_private_get(params->autherr_tpl);
	if (!tpl) {
		tpl = create_autherr_template();
		if (!tpl)
			return;
		g_private_set(params->autherr_tpl, tpl);
	}

	/* feed message fields */
	if (error == AUTH_ERROR_CREDENTIALS)
		severity = "high";
	else
		severity = "medium";
	message = create_message_autherr(tpl, session, text, severity);
	if (!message) {
		return;
	}

	/* send message */
	g_mutex_lock(global_client_mutex);
	prelude_client_send_idmef(global_client, message);
	g_mutex_unlock(global_client_mutex);
	idmef_message_destroy(message);
}

/** @} */
