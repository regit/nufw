/*
** Copyright(C) 2006-2010 EdenWall Technologies
**          written by Eric Leblond <regit@inl.fr>
**                     Pierre Chifflier <chifflier@edenwall.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 3 of the License.
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

#include <glib.h>

#include "x509_std.h"

/**
 * \ingroup NuauthModules
 * \defgroup X509NuauthModules X509 Checking modules
 */

/**
 *
 * \ingroup X509NuauthModules
 * \defgroup X509STDModule X509 standard checking module
 *
 * @{ */



#define DN_LENGTH 256

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	struct x509_std_params *params =
	    (struct x509_std_params *) params_p;
	/*  Free user list */
	if (params) {
		g_free(params->trusted_issuer_dn);
		g_free(params->uid_method);
		g_strfreev(params->uid_method_list);
	}
	g_free(params);

	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct x509_std_params *params = g_new0(struct x509_std_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "X509_std module ($Revision$)");

	/*  set variables */
	params->trusted_issuer_dn = nuauth_config_table_get("nuauth_tls_trusted_issuer_dn");
	params->uid_method = nuauth_config_table_get_or_default("nuauth_tls_uid_method", "UID CN");
	params->uid_method_list = g_strsplit(params->uid_method, " ", 0);

	module->params = (gpointer) params;

	return TRUE;

}


G_MODULE_EXPORT int certificate_check(nussl_session* session,
				      gpointer params_p)
{
#if 0
	struct x509_std_params *params =
	    (struct x509_std_params *) params_p;
	time_t expiration_time, activation_time;

	expiration_time = gnutls_x509_crt_get_expiration_time(cert);
	activation_time = gnutls_x509_crt_get_activation_time(cert);

	if (expiration_time == (time_t)-1 || activation_time == (time_t)-1) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			    "Unable to check certificate date validity"
		    );
		return SASL_DISABLED;
	}

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Certificate validity starts at: %s",
		    ctime(&activation_time)
	    );
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN, "Certificate expires: %s",
		    ctime(&expiration_time));

	/* verify date */
	if (expiration_time < time(NULL)) {
		log_message(INFO, DEBUG_AREA_USER, "Certificate expired at: %s",
			    ctime(&expiration_time));
		/* gnutls_x509_crt_deinit(cert); */
		return SASL_EXPIRED;
	}

	if (activation_time > time(NULL)) {
		log_message(INFO, DEBUG_AREA_USER,
			    "Certificate only activates at: %s",
			    ctime(&activation_time));
		/* gnutls_x509_crt_deinit(cert); */
		return SASL_DISABLED;
	}

	if (params->trusted_issuer_dn) {
		size_t size;
		char dn[DN_LENGTH];
		size = sizeof(dn);
		gnutls_x509_crt_get_issuer_dn(cert, dn, &size);
		if (strcmp(dn, params->trusted_issuer_dn)) {
			log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				    "\tIssuer's DN is not trusted: %s",
				    dn);
			/* gnutls_x509_crt_deinit(cert); */
			return SASL_DISABLED;
		}
	}
#endif
	return SASL_OK;
}

static gchar *certificate_cn_to_uid(nussl_session* session,
					  gpointer params)
{
	size_t size;
	char dn[DN_LENGTH];
	gchar *pointer;
	gchar *delim;

	size = sizeof(dn);
	nussl_get_peer_dn(session, dn, &size);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER, "\tDN: %s", dn);

	/* parse DN and extract username is there is one */
	pointer = g_strrstr_len(dn, DN_LENGTH - 1, "CN=");
	if (pointer) {
		char *string_end = NULL;
		pointer += 3;
		delim = strpbrk(pointer,",/");
		if (delim)
			*delim = '\0';
		string_end = g_strrstr_len(pointer, (DN_LENGTH - 1 ) - (pointer - dn), ",");
		if (string_end) {
			*string_end = 0;
		}
		return g_strdup(pointer);
	}

	return NULL;
}

#ifdef HAVE_OPENSSL

#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>

static gchar *certificate_subjectaltname_upn_to_uid(nussl_session* session,
						    gpointer params)
{
	SSL *ssl = (SSL*)nussl_get_socket(session);
	X509 *cert;
	STACK_OF(GENERAL_NAME) * names;
	int n;

	cert = SSL_get_peer_certificate(ssl);

	if (cert == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get client certificate");
		return NULL;
	}

	names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (names == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" No subjectAltName extension found in certificate");
		return NULL;
	}

	/* subjectAltName contains a sequence of GeneralNames,
	 * as described in RFC 3280 page 107
	 */
	for (n = 0; n < sk_GENERAL_NAME_num(names); n++) {
		GENERAL_NAME *nm = sk_GENERAL_NAME_value(names, n);

		/* all enum values in <openssl/x509v3.h> */
		switch (nm->type) {
		case GEN_OTHERNAME:
		{
			OTHERNAME *othername = nm->d.otherName;

			/* look for the Microsoft Universal Universal Principal Name extension */
			if (NID_ms_upn == OBJ_obj2nid(othername->type_id)) {
				char buf[4096];
				size_t length = sizeof(buf);
				buf[0] = '\0';
				 if (othername->value->type == V_ASN1_UTF8STRING) {
				 	/* length is stored in othername->value->value.utf8string->length */
					snprintf(buf, length, "UPN<%s>", othername->value->value.utf8string->data);
				 }
				log_message(DEBUG, DEBUG_AREA_MAIN,
						" subjectAltName: found %s", buf);
				/* XXX be careful, this is unicode */
				return g_strdup((char*)othername->value->value.utf8string->data);
			}
			log_message(WARNING, DEBUG_AREA_MAIN,
					" subjectAltName unknown othername type: %d",
					nm->type);
			break;
		}
		default:
			log_message(DEBUG, DEBUG_AREA_MAIN,
					" Unknown subjectAltName type: %d", nm->type);
		}
	}

	return NULL;
}

static gchar *certificate_subjectname_uid_to_uid(nussl_session* session,
						    gpointer params)
{
	SSL *ssl = (SSL*)nussl_get_socket(session);
	X509 *cert;
	X509_NAME *subj;
	X509_NAME_ENTRY *entry;
	int idx = -1, lastidx;
	ASN1_STRING *oid;

	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get client certificate");
		return NULL;
	}

	subj = X509_get_subject_name(cert);
	if (subj == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get subject from client certificate");
		return NULL;
	}

	/* find the most specific UID attribute. */
	do {
		lastidx = idx;
		idx = X509_NAME_get_index_by_NID(subj, NID_userId, lastidx);
	} while (idx >= 0);

	if (lastidx < 0) {
		log_message(INFO, DEBUG_AREA_MAIN,
				" Could not get find UID in subject from client certificate");
		return NULL;
	}

	/* extract the value from the last entry */
	entry = X509_NAME_get_entry(subj, lastidx);
	oid = X509_NAME_ENTRY_get_data(entry);
	if (entry == NULL || oid == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get extract UID from client certificate subject");
		return NULL;
	}

	log_message(DEBUG, DEBUG_AREA_MAIN,
			" subjectName: found UID %s", oid->data);

	return g_strdup((char*)oid->data);
}

#else /* HAVE_OPENSSL */

static gchar *certificate_subjectaltname_upn_to_uid(nussl_session* session,
						    gpointer params)
{
	log_message(CRITICAL, DEBUG_AREA_MAIN,
			" x509_std: this uid module is not implemented");

	return NULL;
}

static gchar *certificate_subjectname_uid_to_uid(nussl_session* session,
						    gpointer params)
{
	log_message(CRITICAL, DEBUG_AREA_MAIN,
			" x509_std: this uid module is not implemented");

	return NULL;
}

#endif /* HAVE_OPENSSL */

G_MODULE_EXPORT gchar *certificate_to_uid(nussl_session* session,
					  gpointer params_p)
{
	struct x509_std_params *params = (struct x509_std_params *)params_p;
	const gchar *uid_method;
	char *reply = NULL;
	int i = 0;

	while (params->uid_method_list[i] != NULL) {
		uid_method = params->uid_method_list[i];
		if (strcasecmp(uid_method, "CN") == 0) {
			reply = certificate_cn_to_uid(session, params);
			if (reply)
				return reply;
		}

		if (strcasecmp(uid_method, "UID") == 0) {
			reply = certificate_subjectname_uid_to_uid(session, params);
			if (reply)
				return reply;
		}

		if (strcasecmp(uid_method, "UPN") == 0) {
			reply = certificate_subjectaltname_upn_to_uid(session, params);
			if (reply)
				return reply;
		}

		log_message(CRITICAL, DEBUG_AREA_MAIN,
				" x509_std: unknown uid checking method %s", uid_method);

		i++;
	};

	return NULL;
}

/** @} */
