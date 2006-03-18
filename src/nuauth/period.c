/*
 ** Copyright(C) 2005 INL
 **             written by Eric Leblond <regit@inl.fr>
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

#include "auth_srv.h" 

gboolean is_time_t_in_period(gchar* periodname,time_t time)
{
  if (get_end_of_period_for_time_t(periodname,time)){
        return TRUE;
  } else {
        return FALSE;
  }

}

static inline unsigned int get_start_of_day_from_time_t(time_t time)
{
        return time-time%86400;
}

/**
 * Compute end of period for a given time (second since epoch)
 * - return 0 if time not in period
 * - return -1 if there's no end
 */

static time_t get_end_of_period_item_for_time(struct period_item* perioditem,time_t time)
{
  time_t endtime=-1;
  if (perioditem->start_date != -1) {
        if ((perioditem->start_date>=time) && ((perioditem->end_date<=time)
                        || (perioditem->end_date==-1))
                        ){
                return perioditem->end_date;
        }
  } else {
      struct tm tmtime;
      localtime_r(&time, &tmtime);

      /* compare day if this is not a time only period */
      if (perioditem->start_day!= -1){
          if(perioditem->start_day<=perioditem->end_day){
              if ((tmtime.tm_wday>=perioditem->start_day) && (tmtime.tm_wday <= perioditem->end_day)){
                        endtime=get_start_of_day_from_time_t(time)+86400*(perioditem->end_day-tmtime.tm_wday+1);
              }       
          } else {
              if (tmtime.tm_wday>=perioditem->start_day){
                        endtime=get_start_of_day_from_time_t(time)+86400*(6-tmtime.tm_wday+1+perioditem->end_day);
              }      else  if (tmtime.tm_wday >= perioditem->end_day){
                        endtime=get_start_of_day_from_time_t(time)+86400*(perioditem->end_day-tmtime.tm_wday+1);
              }
          }
      }
      
      /* compare time */
      if (perioditem->start_hour!=-1){
          if ((tmtime.tm_hour>=perioditem->start_hour) && ( (tmtime.tm_hour<=perioditem->end_hour) || (perioditem->end_hour==-1)) ){
              if (perioditem->end_hour==-1){
                  return -1;
              } else {
                  return get_start_of_day_from_time_t(time)+3600*perioditem->end_hour; 
              }
          } else {
              /* out of bound */
                return 0;
          }
      } 
  }
  return endtime;
}

/**
 * return :
 * - 0 if time_t is not in period
 * - -1 if no limit
 */

time_t get_end_of_period_for_time_t(gchar* period,time_t time)
{
  struct period* pperiod=NULL;
  time_t result=-1;
  /* get period in hash */
  pperiod = g_hash_table_lookup(nuauthconf->periods,period);
  if (pperiod==NULL){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER)){
                g_message("period can not be found, typo ?");
        }
  } else {
       GSList* pointer;
       time_t provend;
        /* iter on period_item */
       for( pointer=pperiod->items ;pointer;pointer=pointer->next){
           provend=get_end_of_period_item_for_time((struct period_item*)(pointer->data),time);
           switch (provend){
             case 0:
                     return 0;
             case -1:
                     break;
             default:
                     if ((result == -1) || (provend<result)){
                         result=provend;
                     }
           }
        }
  }
  return result;
}

void free_period(gpointer data)
{
        struct period* period=(struct period*) data;
        g_slist_free(period->items);
        g_free(period->description);
        g_free(period->name);
        g_free(period);
}

gboolean delete_period(GHashTable* periods,gchar* name)
{
        return g_hash_table_remove(periods,name);
}


gboolean destroy_periods(GHashTable* periods)
{
        g_hash_table_destroy(periods);
        return TRUE;
}

gboolean define_new_period(GHashTable* periods,gchar* name,gchar* description)
{
  /* alloc struct */
  struct period* periodelt=g_new0(struct period,1);
  /* insert in hash */
  periodelt->name=g_strdup(name);
  periodelt->description=g_strdup(description);
  periodelt->items=NULL;
  g_hash_table_insert(periods,g_strdup(name),periodelt);
  return TRUE;
}

gboolean add_perioditem_to_period(GHashTable* periods,gchar* name,struct period_item* perioditem)
{
  /* search entry in hash */
        struct period* periodelt = g_hash_table_lookup(periods,name);
  /* add iperioditem to GSList items (but do sanity check on perioditem) */
        if (periodelt && perioditem){
  /* set used to TRUE */
            periodelt->items=g_slist_prepend(periodelt->items,perioditem);
            periodelt->used=TRUE;
        } else {
            if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER)){
                g_message("Can not add period item (%p) to period (%s at %p)",perioditem,name,periodelt);
            }            
                return FALSE;
        }
        return TRUE;
}

/** can have no parameter as a module reload is needed */
GHashTable *init_periods( )
{
  GHashTable * periods=NULL;

  periods=g_hash_table_new_full(g_str_hash,
                  g_str_equal,
                  g_free,
                  (GDestroyNotify) free_period);
  
  modules_parse_periods(periods);

  return periods;
}
