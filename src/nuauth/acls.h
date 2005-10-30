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

#ifndef ACLS_H
#define ACLS_H

void free_acl_cache(gpointer datas);
void free_acl_struct(gpointer datas,gpointer uda);
void free_acl_key(gpointer datas);
gboolean compare_acls(gconstpointer tracking_hdrs1, gconstpointer tracking_hdrs2);

gpointer acl_create_and_alloc_key(connection* kdatas);
inline  guint hash_acl(gconstpointer headers);
void free_acl_list(void * datas);
void get_acls_from_cache (connection* conn_elt);
gpointer acl_duplicate_key(gpointer datas);

#endif
