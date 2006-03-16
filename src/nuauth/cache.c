/*
 ** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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

#include <auth_srv.h>
#include "cache.h"

void free_cache_elt(gpointer data,gpointer userdata)
{
    GFunc free_datas = (GFunc) userdata;
    if(data){
        if (((struct cache_datas*)data)->datas){
            free_datas(((struct cache_datas*)data)->datas,NULL);
        }
        g_free(data);
    }
}

/**
 * compare cache datas
 */
int compare_cache_datas(gconstpointer a, gconstpointer b)
{
    if (a) {
        return (b-((struct cache_datas *)a)->datas); 
    } else {
        return 1;
    }
}

int used_cache_datas(gconstpointer a, gconstpointer b)
{
    return  ((struct cache_datas *)a)->usage; 
}

/**
 * cleaning purpose function, find if an entry is old an unused.
 */
gboolean is_old_cache_entry (gpointer key, gpointer value, gpointer user_data)
{
    /* test if refresh is too late */
    if ( (! ((struct cache_element *)value)->refreshing)
            &&
            ( ((struct cache_element *)value)->refresh_timestamp < time(NULL) )
       ) {
        GSList * stored_datas = ((struct cache_element *)value)->datas;
        /* test if datas are all unused :
         * next element has to be NULL (elsewhere it should have been freed)
         * element usage is NULL */
        if (stored_datas){
            if ( (stored_datas->next == NULL)
                    &&
                    (((struct cache_datas*)(stored_datas->data))->usage == 0 )
               ){
                return TRUE;
            }
        } 
    }
    return FALSE;
}

void cache_insert(struct cache_init_datas* cache_datas, struct cache_message *message)
{
    /* nothing in cache */	
    struct cache_element* cache_elt = NULL;
    gpointer key = NULL;
    /* creating container for datas */
    /* alloc */
    cache_elt = g_new0(struct cache_element,1);
    /* initialize */
    cache_elt->create_timestamp = time(NULL);
    cache_elt->refresh_timestamp = cache_elt->create_timestamp + nuauthconf->datas_persistance;
    cache_elt->refreshing = TRUE;
    cache_elt->datas = NULL;
    key = cache_datas->duplicate_key(message->key);
    g_hash_table_insert(cache_datas->hash,
            key,
            cache_elt);
    /* return we don't have */
    g_async_queue_push( message->reply_queue, null_message );
}    

void cache_get(struct cache_init_datas *cache_datas, 
        struct cache_element *return_list, 
        struct cache_message *message,
        GSList** local_queue)
{
    GSList *cache_datas_list;

    if (return_list->refreshing){
        /* don't answer now. wait till datas is put by working thread
         * put message in local queue
         */
        *local_queue = g_slist_append(*local_queue,message);		
        return;
    }

    if (return_list->refresh_timestamp < time(NULL)){
        /* we need refresh */
        GSList *p_cache_datas_list = NULL;
        cache_datas_list = return_list->datas;
        
        /* we need refresh is element in use ? */
        return_list->refreshing = TRUE;
        
        /* delete very element of the list which is not used */
        for(p_cache_datas_list = g_slist_find_custom(cache_datas_list,GUINT_TO_POINTER(0),used_cache_datas);
                p_cache_datas_list;
                p_cache_datas_list = g_slist_find_custom(cache_datas_list,GUINT_TO_POINTER(0),used_cache_datas)){
            if (((struct cache_datas*)p_cache_datas_list->data)->datas){
                GFunc free_datas = (GFunc) *(cache_datas->delete_elt);
                free_datas(((struct cache_datas*)p_cache_datas_list->data)->datas,NULL);
                cache_datas_list = g_slist_remove(cache_datas_list,p_cache_datas_list->data);
            } else {
                cache_datas_list = g_slist_remove(cache_datas_list,p_cache_datas_list->data);
            }
        }
        return_list->datas = cache_datas_list;
        /* prepend null container element */
        /* and ask refresh */		
        g_async_queue_push(message->reply_queue,null_message);
    } else {
        cache_datas_list = return_list->datas;

        /* cache is clean, increase usage */
        ((struct cache_datas *)(cache_datas_list->data))->usage++;
        
        /* and push datas to queue */
        if (((struct cache_datas *)(cache_datas_list->data))->datas){
            g_async_queue_push(message->reply_queue,
                    ((struct cache_datas *)(cache_datas_list->data))->datas);
        } else {
            g_async_queue_push(message->reply_queue,null_queue_datas);
        }
    }
}    

void cache_free_message(struct cache_init_datas *cache_datas, 
        struct cache_element *return_list,
        struct cache_message *message)
{
    GSList* cache_datas_list = return_list->datas;
    GSList* concerned_datas = g_slist_find_custom (cache_datas_list,
            message->datas,
            compare_cache_datas);
    struct cache_datas *data = (struct cache_datas *)concerned_datas->data;

    if (concerned_datas == NULL) return;
        
    if (data->usage == 1){
        /* if it is not actual element, we delete it */
        if (concerned_datas != cache_datas_list){
            /* free datas */
            cache_datas->delete_elt(data->datas, NULL);
            g_free(data);
            return_list->datas  = g_slist_delete_link(return_list->datas,concerned_datas);
        } else {
            /* it's actual element, we do anything but decrease usage */
            data->usage = 0;
        }
    } else {
        data->usage--;
    }
}    

void cache_refresh(struct cache_init_datas *cache_datas, 
        struct cache_element *return_list,
        struct cache_message *message,
        GSList** local_queue)
{
    GSList* p_local_queue;

    /* fine we really wait message and can update */
    /* alloc cache_datas element */
    struct cache_datas * elt = g_new0(struct cache_datas,1);

    /* update NULL element waiting for completion */
    elt->datas = message->datas;
    elt->usage=1;
    /* answer to waiting thread */
    for (p_local_queue = *local_queue;p_local_queue;p_local_queue = p_local_queue->next){
        struct cache_message* datas = (struct cache_message*)(p_local_queue->data);
        /*  where message->key is the same reply */
        if (cache_datas->equal_key(message->key,datas->key)){
            g_async_queue_push(datas->reply_queue,
                    message->datas);
            elt->usage++;
            /*remove  message */
            p_local_queue->data=NULL;
        }
    }

    *local_queue = g_slist_remove_all(*local_queue, NULL);
    return_list->datas = g_slist_prepend(return_list->datas,elt);
    return_list->refreshing = FALSE;
    return_list->refresh_timestamp = time(NULL)+nuauthconf->datas_persistance;
}    

/**
 * Thread function that wait for cache query.
 *
 * The algorithm is the following :
 *      - If we found something, we send it back
 *      - If not we warn the client to look by itself and give us the answer when it has found it
 */
void cache_manager (gpointer datas) {
    struct cache_init_datas *cache_datas = datas;
    struct cache_message *message;
    struct cache_element *return_list;
    GSList* local_queue = NULL;

    /* wait for message */
    while ( (message = g_async_queue_pop(cache_datas->queue)) ) {
        switch(message->type){
            case GET_MESSAGE:
                /* look for datas */
                return_list = g_hash_table_lookup(cache_datas->hash,message->key);	
                if (return_list == NULL) {
                    cache_insert(cache_datas, message);
                } else {
                    cache_get(cache_datas, return_list, message, &local_queue);
                }
                break;

            case INSERT_MESSAGE:
                /* look for datas */
                return_list = g_hash_table_lookup(cache_datas->hash, message->key);	
                g_assert(return_list != NULL);
                if (return_list->refreshing) {
                    cache_refresh(cache_datas, return_list, message, &local_queue);                    
                } else {
                    g_error("a thread lost its mind");
                }
                cache_datas->free_key(message->key);
                g_free(message);
                break;

            case FREE_MESSAGE:
                return_list = g_hash_table_lookup(cache_datas->hash,message->key);	
                if (return_list != NULL){
                    cache_free_message(cache_datas, return_list, message);
                } 
                cache_datas->free_key(message->key);
                g_free(message);
                break;

            case REFRESH_MESSAGE:
                /* iter on each element */
                g_hash_table_foreach_remove (
                        cache_datas->hash, is_old_cache_entry, NULL);
                g_free(message);
                break;
        }
    }
}

void clear_cache (struct cache_init_datas *cache_datas)
{
    struct cache_message *message;

    if (cache_datas == NULL)
        return;
    
    /* TODO: clear queue ??? */
	g_hash_table_destroy (cache_datas->hash);
}

