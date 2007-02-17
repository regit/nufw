/*
 ** Copyright(C) 2003-2006, INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@gryzor.com>
 **
 **    INL http://www.inl.fr/
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

#include <auth_srv.h>
#include "cache.h"

/**
 * \ingroup Nuauth
 * \defgroup Cache Cache system
 *
 * @{
 */

/**
 * \file cache.c
 * \brief Generic cache system
 *
 * An implementation of a generic cache system
 */
void cache_entry_content_destroy(cache_entry_content_t * item,
				 GFunc free_datas)
{
	if (item != NULL && item->datas != NULL) {
		free_datas(item->datas, NULL);
		item->datas = NULL;
	}
	g_free(item);
}

/**
 * compare cache datas
 */
int cache_entry_content_compare(const cache_entry_content_t * content,
				gconstpointer data)
{
	if (content) {
		return (data - content->datas);
	} else {
		return 1;
	}
}

int cache_entry_content_used(const cache_entry_content_t * content,
			     gconstpointer b)
{
	return content->usage;
}

/**
 * cleaning purpose function, find if an entry is old an unused.
 */
gboolean cache_entry_is_old(gpointer key, gpointer value,
			    gpointer user_data)
{
	cache_entry_t *entry = value;
	cache_entry_content_t *data;
	GSList *list;

	/* test if refresh is too late */
	if (entry->refreshing || (time(NULL) <= entry->refresh_timestamp)) {
		return FALSE;
	}

	list = entry->datas;
	if (!list) {
		return FALSE;
	}

	/* test if datas are all unused */
	data = list->data;
	if ((list->next == NULL) && (data->usage == 0)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void cache_insert(cache_class_t * this, struct cache_message *message)
{
	/* nothing in cache */
	cache_entry_t *cache_elt;
	gpointer key;

	/* creating container for datas */
	cache_elt = g_new0(cache_entry_t, 1);
	cache_elt->create_timestamp = time(NULL);
	cache_elt->refresh_timestamp =
	    cache_elt->create_timestamp + nuauthconf->datas_persistance;
	cache_elt->refreshing = TRUE;
	cache_elt->datas = NULL;
	key = this->duplicate_key(message->key);
	g_hash_table_insert(this->hash, key, cache_elt);

	/* return we don't have */
	g_async_queue_push(message->reply_queue, null_message);
}

void cache_get(cache_class_t * this,
	       cache_entry_t * entry,
	       struct cache_message *message, GSList ** local_queue)
{
	GSList *list;
	cache_entry_content_t *item;

	if (entry->refreshing) {
		/* don't answer now. wait till datas is put by working thread
		 * put message in local queue */
		*local_queue = g_slist_append(*local_queue, message);
		return;
	}
	list = entry->datas;

	if (entry->refresh_timestamp < time(NULL)) {
		/* we need refresh */
		GSList *iter;

		/* we need refresh is element in use ? */
		entry->refreshing = TRUE;

		/* delete all elements of the list which are unused */
		do {
			/* find unused items */
			iter =
			    g_slist_find_custom(list, GUINT_TO_POINTER(0),
						(GCompareFunc)
						cache_entry_content_used);
			if (iter == NULL) {
				break;
			}

			/* delete item if needed */
			item = iter->data;
			if (item->datas != NULL) {
				GFunc free_datas =
				    (GFunc) this->delete_elt;
				free_datas(item->datas, NULL);
			}
			list = g_slist_remove(list, item);
		} while (1);
		entry->datas = list;

		/* prepend null container element, and ask refresh */
		g_async_queue_push(message->reply_queue, null_message);
	} else {
		item = list->data;

		/* cache is clean, increase usage */
		item->usage++;

		/* and push datas to queue */
		if (item->datas) {
			g_async_queue_push(message->reply_queue,
					   item->datas);
		} else {
			g_async_queue_push(message->reply_queue,
					   null_queue_datas);
		}
	}
}

void cache_message_destroy(cache_class_t * this,
			   cache_entry_t * entry,
			   struct cache_message *message)
{
	cache_entry_content_t *content;
	GSList *cache_datas_list = entry->datas;
	GSList *concerned_datas = g_slist_find_custom(cache_datas_list,
						      message->datas,
						      (GCompareFunc)
						      cache_entry_content_compare);
	if (concerned_datas == NULL) {
		return;
	}

	content = concerned_datas->data;
	if (content->usage != 1) {
		content->usage--;
		return;
	}

	/* it's the most recent element, we do anything but decrease usage */
	if (concerned_datas == cache_datas_list) {
		content->usage = 0;
		return;
	}

	/* free datas */
	this->delete_elt(content->datas, NULL);
	g_free(content);
	entry->datas = g_slist_delete_link(entry->datas, concerned_datas);
}

void cache_refresh(cache_class_t * this,
		   cache_entry_t * entry,
		   struct cache_message *message, GSList ** local_queue)
{
	GSList *iter;

	/* fine we really wait message and can update, alloc cache_datas element */
	cache_entry_content_t *elt = g_new0(cache_entry_content_t, 1);

	/* update NULL element waiting for completion */
	elt->datas = message->datas;
	elt->usage = 1;

	/* answer to waiting thread */
	for (iter = *local_queue; iter; iter = iter->next) {
		struct cache_message *datas =
		    (struct cache_message *) (iter->data);

		/*  where message->key is the same reply */
		if (this->equal_key(message->key, datas->key)) {
			g_async_queue_push(datas->reply_queue,
					   message->datas);
			elt->usage++;
			/* set data to NULL to initiate message removal */
			iter->data = NULL;
		}
	}

	/* remove message with data equal to NULL */
	*local_queue = g_slist_remove_all(*local_queue, NULL);
	entry->datas = g_slist_prepend(entry->datas, elt);
	entry->refreshing = FALSE;
	entry->refresh_timestamp =
	    time(NULL) + nuauthconf->datas_persistance;
}

/**
 * Thread function that wait for cache query.
 *
 * The algorithm is the following :
 *      - If we found something, we send it back
 *      - If not we warn the client to look by itself and give us the answer when it has found it
 */
void cache_manager(cache_class_t * this)
{
	struct cache_message *message;
	cache_entry_t *entry;
	GSList *local_queue = NULL;

	/* wait for message */
	while (1) {
		message = g_async_queue_pop(this->queue);
		if (message == NULL) {
			/* should never appens */
			continue;
		}
		switch (message->type) {
		case GET_MESSAGE:
			/* look for datas */
			entry =
			    g_hash_table_lookup(this->hash, message->key);
			if (entry == NULL) {
				cache_insert(this, message);
			} else {
				cache_get(this, entry, message,
					  &local_queue);
			}
			break;

		case INSERT_MESSAGE:
			/* look for datas */
			entry =
			    g_hash_table_lookup(this->hash, message->key);
			g_assert(entry != NULL);
			if (entry->refreshing) {
				cache_refresh(this, entry, message,
					      &local_queue);
			} else {
				g_error("a thread lost its mind");
			}
			this->free_key(message->key);
			g_free(message);
			break;

		case FREE_MESSAGE:
			entry =
			    g_hash_table_lookup(this->hash, message->key);
			if (entry != NULL) {
				cache_message_destroy(this, entry,
						      message);
			}
			this->free_key(message->key);
			g_free(message);
			break;

		case REFRESH_MESSAGE:
			/* iter on each element */
			g_hash_table_foreach_remove(this->hash,
						    cache_entry_is_old,
						    NULL);
			g_free(message);
			break;
		}
	}
}

void cache_destroy(cache_class_t * this)
{
	struct cache_message *message;

	if (this == NULL)
		return;

	while ((message = g_async_queue_try_pop(this->queue)) != NULL) {
		g_free(message);
	}

	g_hash_table_destroy(this->hash);
}

/** @} */
