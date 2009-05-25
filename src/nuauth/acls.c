/*
 ** Copyright(C) 2004-2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

/**
 * \addtogroup Cache
 * @{
 */

/*! \file acls.c
 *  \brief Acls manipulations and cache

 *  It implements the functions needed to activate cache for acls and basic
 *  acl manipulations tasks


*/



#include <auth_srv.h>
#define USE_JHASH2
#include <jhash.h>
#include "cache.h"

/**
 * identify a acl in the cache
 */
struct acl_key {
	tracking_t *acl_tracking;
	/** operating system name. */
	gchar *sysname;
	/** operating system release. */
	gchar *release;
	/** operating system version. */
	gchar *version;
	/** application name.
	 *
	 * application full path
	 */
	gchar *appname;
	gchar *appsig;
	/*
	 * interfaces
	 */
	iface_nfo_t iface_nfo;
};

/**
 * Function used for connection hash.
 *
 * Params : a "struct acl_key"
 * Return : the associated key
 */
guint32 hash_acl(gconstpointer key)
{
	tracking_t *tracking =
	    (tracking_t *) ((struct acl_key *) key)->acl_tracking;
	return jhash2((guint32 *) tracking,
		      (sizeof(struct in6_addr) * 2 + 4) / 4, tracking->dest);
}

/**
 * Internal string comparison function
 */
gint strcmp_null(gchar * a, gchar * b)
{
	if (a == NULL) {
		if (b == NULL)
			return FALSE;
		else
			return TRUE;
	} else {
		if (b)
			return strcmp(a, b);
		else
			return TRUE;
	}
}

gboolean compare_acls(gconstpointer a, gconstpointer b)
{
	struct acl_key *acl_key1 = (struct acl_key *) a;
	struct acl_key *acl_key2 = (struct acl_key *) b;

	if (!tracking_equal
	    (acl_key1->acl_tracking, acl_key2->acl_tracking)) {
		return FALSE;
	}
	if (strcmp_null(acl_key1->appname, acl_key2->appname))
		return FALSE;
	if (strcmp_null(acl_key1->sysname, acl_key2->sysname))
		return FALSE;
	if (strcmp_null(acl_key1->release, acl_key2->release))
		return FALSE;
	if (strcmp_null(acl_key1->version, acl_key2->version))
		return FALSE;
	if (compare_iface_nfo_t(&acl_key1->iface_nfo, &acl_key2->iface_nfo)
		== NU_EXIT_ERROR)
		return FALSE;
	return TRUE;
}

void free_acl_key(gpointer datas)
{
	struct acl_key *kdatas = (struct acl_key *) datas;
	g_free(kdatas->acl_tracking);
	g_free(kdatas->sysname);
	g_free(kdatas->release);
	g_free(kdatas->version);
	g_free(kdatas->appname);
	g_free(kdatas);
}

void free_one_acl_group(struct acl_group *acl, gpointer userdata)
{
	if (acl) {
		g_slist_free(acl->users);
		g_slist_free(acl->groups);
		g_free(acl->period);
		g_free(acl->log_prefix);
		g_free(acl);
	}
}

void free_acl_groups(GSList * acl_groups, gpointer userdata)
{
	g_slist_foreach(acl_groups, (GFunc) free_one_acl_group, NULL);
	g_slist_free(acl_groups);
}

/**
 * destroy function for acl cache datas.
 * hash value is a gslist of entry
 */
void free_acl_cache(cache_entry_t * entry)
{
	GSList *list = entry->datas;
	if (list != NULL) {
		g_slist_foreach(list, (GFunc) cache_entry_content_destroy,
				free_acl_groups);
		g_slist_free(list);
	}
	g_free(entry);
}

gpointer acl_create_and_alloc_key(connection_t * kdatas)
{
	struct acl_key key;
	key.acl_tracking = &(kdatas->tracking);
	key.sysname = kdatas->os_sysname;
	key.release = kdatas->os_release;
	key.version = kdatas->os_version;
	key.appname = kdatas->app_name;
	key.appsig = kdatas->app_sig;
	duplicate_iface_nfo(&(key.iface_nfo), &(kdatas->iface_nfo));
	return acl_duplicate_key(&key);
}


gpointer acl_duplicate_key(gpointer datas)
{
	struct acl_key *key = g_new0(struct acl_key, 1);
	struct acl_key *kdatas = (struct acl_key *) datas;

	key->acl_tracking =
	    g_memdup(kdatas->acl_tracking,
		     sizeof(*(kdatas->acl_tracking)));
	/* Normalize source port */
	key->acl_tracking->source = 1024;
	key->sysname = g_strdup(kdatas->sysname);
	key->release = g_strdup(kdatas->release);
	key->version = g_strdup(kdatas->version);
	key->appname = g_strdup(kdatas->appname);
	duplicate_iface_nfo(&key->iface_nfo, &kdatas->iface_nfo);
	return key;
}

/**
 * ask the acl cache information about a received packet.
 *
 */
void get_acls_from_cache(connection_t * conn_elt)
{
	struct cache_message message;
	/* Going to ask to the cache */
	/* prepare message */
	message.type = GET_MESSAGE;
	message.key = acl_create_and_alloc_key(conn_elt);
	message.datas = NULL;
	message.reply_queue = g_private_get(nuauthdatas->aclqueue);
	if (message.reply_queue == NULL) {
		message.reply_queue = g_async_queue_new();
		g_private_set(nuauthdatas->aclqueue, message.reply_queue);
	}
	/* send message */
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			  "[acl cache] going to send cache request");
	g_async_queue_push(nuauthdatas->acl_cache->queue, &message);
	/* lock */
	g_atomic_int_inc(&(myaudit->cache_req_nb));
	/*release */
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			  "[acl cache] request sent");
	/* wait for answer */
	conn_elt->acl_groups = g_async_queue_pop(message.reply_queue);

	if (conn_elt->acl_groups == null_queue_datas) {
		conn_elt->acl_groups = NULL;
	} else if (conn_elt->acl_groups == null_message) {
		struct cache_message *rmessage;

		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				  "[acl cache] We are about to search entry");
		/* cache wants an update
		 * external check of acl */
		conn_elt->acl_groups = modules_acl_check(conn_elt);

		rmessage = g_new0(struct cache_message, 1);
		rmessage->type = INSERT_MESSAGE;
		rmessage->key = message.key;
		rmessage->datas = conn_elt->acl_groups;
		rmessage->reply_queue = NULL;
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				  "[acl cache] answering for key %p",
				  rmessage->key);
		/* reply to the cache */
		g_async_queue_push(nuauthdatas->acl_cache->queue,
				   rmessage);
		return;
	} else {
		g_atomic_int_inc(&(myaudit->cache_hit_nb));
	}
	/* free initial key */
	free_acl_key(message.key);
}

int init_acl_cache()
{
	GThread *acl_cache_thread;
	/* create acl cache thread */
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN, "creating acl cache thread");
	nuauthdatas->acl_cache = g_new0(cache_class_t, 1);
	nuauthdatas->acl_cache->hash =
	    g_hash_table_new_full((GHashFunc) hash_acl, compare_acls,
				  (GDestroyNotify) free_acl_key,
				  (GDestroyNotify) free_acl_cache);
	nuauthdatas->acl_cache->queue = g_async_queue_new();
	nuauthdatas->acl_cache->delete_elt = (GFunc) free_acl_groups;
	nuauthdatas->acl_cache->duplicate_key = acl_duplicate_key;
	nuauthdatas->acl_cache->free_key = free_acl_key;
	nuauthdatas->acl_cache->equal_key = compare_acls;


	acl_cache_thread = g_thread_create((GThreadFunc) cache_manager,
					   nuauthdatas->acl_cache,
					   FALSE, NULL);
	if (!acl_cache_thread)
		exit(EXIT_FAILURE);
	return 1;
}

/** @} */
