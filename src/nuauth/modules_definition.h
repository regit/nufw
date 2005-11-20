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

GSList* ip_auth_modules;

GSList* user_logs_modules;


GMutex *modules_mutex;

typedef int user_check_callback (const char *user, const char *pass,unsigned passlen,uint16_t *uid,GSList **groups);

typedef GSList * acl_check_callback (connection* element);

/* ip auth */
typedef gchar* ip_auth_callback (tracking * header);

typedef int user_logs_callback (connection element, int state);

#endif
