/** 
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
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
#include <jhash.h>
#include "cache.h"

/**
 * used when destroying value from hash
 * hash value is a gslist of entry
 */

void free_user_struct(gpointer datas,gpointer userdata)
{
	/* free user group */
	if (((struct user_cached_datas*)datas)->groups){
		g_slist_free(((struct user_cached_datas*)datas)->groups);
	}
	g_free(datas);
}

void free_user_cache(gpointer datas)
{
	GSList * dataslist=((struct cache_element *)datas)->datas;
	if ( dataslist  != NULL ){
		g_slist_foreach(dataslist,(GFunc) free_cache_elt,free_user_struct);
		g_slist_free (dataslist);
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
			g_message ("user datas freed %p\n",dataslist);
#endif
	}
	g_free(datas);
}


/**
 * handle discussion with user cache 
 */

void get_users_from_cache (connection_t* conn_elt)
{
	struct cache_message message;
	/* Going to ask to the cache */
	/* prepare message */
	message.type=GET_MESSAGE;
	message.key=conn_elt->username;
	message.datas=NULL;
	message.reply_queue=g_private_get(nuauthdatas->userqueue);
	if (message.reply_queue==NULL){
		message.reply_queue=g_async_queue_new();
		g_private_set(nuauthdatas->userqueue,message.reply_queue);
	}
	/* send message */
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
		g_message("[user cache] going to send cache request for %s\n",conn_elt->username);
#endif
	g_async_queue_push (nuauthdatas->user_cache->queue,&message);
	/* lock */
	g_atomic_int_inc(&(myaudit->cache_req_nb));
	/*release */
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
		g_message("[user cache] request sent");
#endif
	/* wait for answer */
	conn_elt->cacheduserdatas=g_async_queue_pop(message.reply_queue);
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
		g_message("[user cache] cache answered");
#endif
	if (conn_elt->cacheduserdatas == null_queue_datas){
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
			g_message("[user cache] setting cached user datas to NULL\n");
#endif
		conn_elt->cacheduserdatas=NULL;
	} 
	/* check if answer is NULL */
	if (conn_elt->cacheduserdatas==null_message){
		struct cache_message * rmessage;
		struct user_cached_datas*  userdatas=g_new0(struct user_cached_datas,1);

		userdatas->groups=NULL;
		userdatas->uid=0;

		/* cache wants an update 
		 * external check of user */
		if (modules_user_check(conn_elt->username,NULL,0,&(userdatas->uid),&(userdatas->groups))!=SASL_OK){
			/*user has not been found or problem occurs we must fail 
			 * returning NULL is enough (don't want to be DOSsed)*/
			if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
				g_message("User not found");
			}

            /* GRYZOR asks : shouldnt we just leave here? */
		}
		rmessage=g_new0(struct cache_message,1);
		rmessage->type=INSERT_MESSAGE;
		rmessage->key=g_strdup(conn_elt->username);
		rmessage->datas=userdatas;
		rmessage->reply_queue=NULL;
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
			g_message("[user cache] answering for key %p\n",rmessage->key);
#endif
		/* reply to the cache */
		g_async_queue_push(nuauthdatas->user_cache->queue,rmessage);
		/* fill connection datas */
		conn_elt->user_groups=userdatas->groups;
		conn_elt->user_id=userdatas->uid;
		conn_elt->cacheduserdatas=userdatas;
	} else {
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
			g_message("[user cache] cache call succedeed");
		}
#endif
		conn_elt->user_groups=(conn_elt->cacheduserdatas)->groups;
		conn_elt->user_id=(conn_elt->cacheduserdatas)->uid;

		g_atomic_int_inc(&(myaudit->cache_hit_nb));
	}
}

gpointer user_duplicate_key(gpointer datas)
{
	return (void*) g_strdup((gchar *)datas);
}

int init_user_cache()
{
	GThread *user_cache_thread;
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("creating user cache thread");
		nuauthdatas->user_cache=g_new0(struct cache_init_datas,1);
		nuauthdatas->user_cache->hash=g_hash_table_new_full((GHashFunc)g_str_hash,
				g_str_equal,
				(GDestroyNotify) g_free,
				(GDestroyNotify) free_user_cache); 
		nuauthdatas->user_cache->queue=g_async_queue_new();
		nuauthdatas->user_cache->delete_elt=free_user_struct;
		nuauthdatas->user_cache->duplicate_key=user_duplicate_key;
		nuauthdatas->user_cache->free_key=g_free;
                nuauthdatas->user_cache->equal_key=g_str_equal;


		user_cache_thread = g_thread_create ( (GThreadFunc) cache_manager,
				nuauthdatas->user_cache,
				FALSE,
				NULL);
		if (! user_cache_thread )
			exit(EXIT_FAILURE);
		return 1;
}
