/*
 ** Copyright(C) 2005-2006 Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
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

#ifndef MODULES_DEFINITION_H
#define MODULES_DEFINITION_H

/** \addtogroup NuauthModules
 * @{
 */

#include "modules.h"

GMutex *modules_mutex;

/** callback definition */

typedef gboolean init_module_from_conf_t(module_t * module);

typedef int user_check_callback(const char *user, const char *pass,
				unsigned passlen, user_session_t *session, gpointer params);

typedef GSList *get_user_groups_callback(const char *user,
					 gpointer params);

typedef uint32_t get_user_id_callback(const char *user, gpointer params);

typedef GSList *acl_check_callback(connection_t * element,
				   gpointer params);

typedef void define_period_callback(GHashTable * periods, gpointer params);

/* ip auth */
typedef gchar *ip_auth_callback(tracking_t * header, gpointer params);

typedef int user_logs_callback(void *element, tcp_state_t state,
			       gpointer params);
typedef int user_session_logs_callback(user_session_t * element,
				       session_state_t state,
				       gpointer params);

/* certificate stuff */

typedef int certificate_check_callback(nussl_session *nussl,
				       gpointer params);
/* certificate to uid function */
typedef gchar *certificate_to_uid_callback(nussl_session *nussl,
					   gpointer params);

typedef nu_error_t user_session_modify_callback(user_session_t * session,
						gpointer params);

typedef nu_error_t finalize_packet_callback(connection_t * session,
					    gpointer params);

typedef void auth_error_log_callback(user_session_t * session,
				     nuauth_auth_error_t error,
				     const char *message, gpointer params);

typedef int postauth_proto_callback(user_session_t * session, gpointer params);
/** @} */

#endif
