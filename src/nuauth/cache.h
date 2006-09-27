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

#ifndef CACHE_H
#define CACHE_H

/**
 * \addtogroup NuauthCache
 * @{
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

void cache_entry_content_destroy(struct cache_datas* item, GFunc free_datas);

typedef void (*CacheDeleteFunc)(gpointer, gpointer);

/**
 * struct needed for initialisation of cache manager occurence
 */
struct cache_init_datas {
	GAsyncQueue * queue;
	GHashTable*  hash;
	CacheDeleteFunc delete_elt;
	void* (*duplicate_key)(gpointer);
	void (*free_key)(gpointer);
	gboolean (*equal_key)(gconstpointer,gconstpointer);
};

void cache_manager(struct cache_init_datas *this);
void cache_destroy(struct cache_init_datas *datas);

/**
 * generic message send between thread working with the
 * cache system
 */
struct cache_message {
	guint type;                /*< message type */
	gpointer key;              /*< key that identify datas in hash */
	gpointer datas;            /*< datas to store */
	GAsyncQueue* reply_queue;  /*< reply has to be sent to */
};

gpointer null_message;
gpointer null_queue_datas;

/** @} */

#endif

