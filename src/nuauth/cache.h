/*
 ** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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


struct cache_element {
	GSList* datas;
	time_t create_timestamp;
	time_t refresh_timestamp;
	gboolean refreshing;
};

struct cache_datas {
    gpointer datas;
    guint usage;
};


gboolean is_old_cache_entry                    (gpointer key,
    gpointer value,
    gpointer user_data);

