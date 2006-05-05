/*
** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
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

#ifndef PARSING_H 
#define PARSING_H

/* parsing function */
struct in6_addr* generate_inaddr_list(gchar* gwsrv_addr);
gboolean check_inaddr_in_array(struct in6_addr *check_ip, struct in6_addr *iparray);
gboolean check_string_in_array(gchar* checkstring,gchar** stringarray);

/**
 * Check validity of data before inserting them to SQL
 * This allocates a new string.
 * Returns NULL is the original string contains ' or ;
 * Else returns escaped char (with glib function g_strescape()
 */
gchar *string_escape(gchar *orig);

#endif
