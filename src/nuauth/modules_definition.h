/*
 ** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
 **                  INL http://www.inl.fr/
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

#ifndef MODULES_DEFINITION_H
#define MODULES_DEFINITION_H

GSList* user_check_modules;

GSList* acl_check_modules;

/** this is the list of module which are used to define time period
 * as this is used by other modules there is no need to have a special locking 
 * mechanism for them. It will not be used if usage of all other modules (specifically acls and user one) 
 * is blocked.
 */
GSList* period_modules;

GSList* ip_auth_modules;

GSList* user_logs_modules;
GSList* user_session_logs_modules;

GSList* certificate_check_modules;
GSList* certificate_to_uid_modules;

GMutex *modules_mutex;

/** callback definition */

typedef gboolean init_module_from_conf_t (module_t* module);

typedef int user_check_callback (const char *user, const char *pass,unsigned passlen,uint32_t *uid,GSList **groups,gpointer params);

typedef GSList * acl_check_callback (connection_t* element,gpointer params);

typedef void define_period_callback (GHashTable* periods,gpointer params);

/* ip auth */
typedef gchar* ip_auth_callback (tracking_t * header,gpointer params);

typedef int user_logs_callback (connection_t* element, tcp_state_t state,gpointer params);
typedef int user_session_logs_callback (user_session* element, session_state_t state,gpointer params);

/* certificate stuff */

typedef int certificate_check_callback (gnutls_session session, gnutls_x509_crt cert,gpointer params);
/* certificate to uid function */
typedef gchar* certificate_to_uid_callback (gnutls_session session, gnutls_x509_crt cert,gpointer params);


#endif
