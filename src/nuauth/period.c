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

static inline unsigned int get_hour_of_day_from_time_t(time_t time)
{
        time_t modt=time%86400;
        return modt/3600;
}

static inline unsigned int get_start_of_day_from_time_t(time_t time)
{
        return time%86400;
}

/**
 * return 0 if time not in period
 */

static time_t get_end_of_period_item_for_time(struct period_item* perioditem,time_t time)
{
  unsigned int htime=0;
  time_t endtime=-1;
  if (perioditem->start_date != -1) {
        if ((perioditem->start_date>=time) && (perioditem->end_date<=time)){
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
        htime = get_hour_of_day_from_time_t(time);
          if ((htime>=perioditem->start_hour) && (htime<=perioditem->end_hour)){
              return get_start_of_day_from_time_t(time)+3600*perioditem->end_hour; 
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
  time_t result=0;
  /* get period in hash */
  pperiod = g_hash_table_lookup(nuauthconf->periods,period);
  if (pperiod==NULL){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER)){
                g_message("period can not be found, typo ?");
        }
  } else {
       GSList* pointer=pperiod->items;
       time_t provend;
        /* iter on period_item */
        for(;pointer;pointer=pointer->next){
                provend=get_end_of_period_item_for_time((struct period_item*)pointer,time);
                if(provend==0){
                    return 0;
                } else {
                        if ((result == 0) || (provend<result)){
                                result=provend;
                        }
                }
        }
  }
  return result;
}

gboolean define_new_period(gchar* name,gchar* description)
{
        return TRUE;
}

gboolean add_perioditem_to_period(gchar* name,struct period_item* perioditem)
{
        return TRUE;
}

