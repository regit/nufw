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

#ifndef PERIOD_H
#define PERIOD_H

/* period are weekly based */

/** define a period item
 *
 * This is a interval of days linked to a hour period
 *
 */
struct period_item {
    time_t duration; /**< specify that connection will expire after duration delay */
    time_t start_date; /**< specify an interval in date, set to -1 to ignore */
    time_t end_date; /**< end of date interval set to -1 to ignore */
    int start_day; /**< week day start, set to -1 to ignore interval check, day from O (sunday) to 6 (saturday) */
    int end_day; /**< week day end, set to -1 to ignore */
    char start_hour; /**< 0-24 start hour, set to -1 to ignore */
    char end_hour; /**< O-24 end hour, set to -1 to ignore */
};

/**
 * define a period
 * - this is a GSList of period_item
 * - a name
 * - a description
 * - a flag to indicate if is is used or not
 */
struct period {
    GSList* items;
    gchar* description;
    gchar* name;
    gboolean used;
};

gboolean is_time_t_in_period(gchar* period,time_t time);

time_t get_end_of_period_for_time_t(gchar* period,time_t time);

gboolean define_new_period(GHashTable* periods,gchar* name,gchar* description);

gboolean add_perioditem_to_period(GHashTable* periods,gchar* name,struct period_item* perioditem);

gboolean delete_period(GHashTable* periods,gchar* name);

gboolean destroy_periods(GHashTable* periods);
GHashTable * init_periods();

#endif
