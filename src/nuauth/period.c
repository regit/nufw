/*
 ** Copyright(C) 2005-2007 INL
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

#include "auth_srv.h"

/**
 * \addtogroup NuauthConntrack
 * @{
 */

/**
 * \file period.c
 * \brief Provide a set of functions for period and time calculation
 */

static GStaticMutex period_mutex = G_STATIC_MUTEX_INIT;

static inline unsigned int get_start_of_day_from_time_t(time_t pckt_time)
{
	return pckt_time - pckt_time % 86400;
}

/**
 * Compute end of period for a given time (second since epoch)
 *
 * \return return value of end period
 *  - 0 if time not in period
 *  - -1 if there's no end
 */

static time_t get_end_of_period_item_for_time(struct period_item
					      *perioditem,
					      time_t pckt_time)
{
	time_t endtime = -1;
	if (perioditem->duration > 0) {
		endtime = pckt_time + perioditem->duration;
		return endtime;
	}
	if ((perioditem->start_date != -1) || (perioditem->end_date != -1)) {
		if (perioditem->start_date != -1) {
			if (perioditem->start_date > pckt_time) {
				return 0;
			}
		}
		if (perioditem->end_date != -1) {
			if (perioditem->end_date >= pckt_time) {
				return perioditem->end_date;
			} else {
				return 0;
			}
		}
	} else {
		struct tm tmtime;
		localtime_r(&pckt_time, &tmtime);

		/* compare day if this is not a time only period */
		if (perioditem->start_day != -1) {
			if (perioditem->start_day <= perioditem->end_day) {
				if ((tmtime.tm_wday >=
				     perioditem->start_day)
				    && (tmtime.tm_wday <=
					perioditem->end_day)) {
					endtime =
					    get_start_of_day_from_time_t
					    (pckt_time) +
					    86400 * (perioditem->end_day -
						     tmtime.tm_wday + 1);
				} else {
					return 0;
				}
			} else {
				if (tmtime.tm_wday >=
				    perioditem->start_day) {
					endtime =
					    get_start_of_day_from_time_t
					    (pckt_time) + 86400 * (6 -
								   tmtime.
								   tm_wday
								   + 1 +
								   perioditem->
								   end_day);
				} else if (tmtime.tm_wday >=
					   perioditem->end_day) {
					endtime =
					    get_start_of_day_from_time_t
					    (pckt_time) +
					    86400 * (perioditem->end_day -
						     tmtime.tm_wday + 1);
				} else {
					return 0;
				}
			}
		}

		/* compare time */
		if (perioditem->start_hour != -1) {
			if ((tmtime.tm_hour >= perioditem->start_hour)
			    && ((tmtime.tm_hour < perioditem->end_hour)
				|| (perioditem->end_hour == -1))) {
				if (perioditem->end_hour == -1) {
					return endtime;
				} else {
					return
					    get_start_of_day_from_time_t
					    (pckt_time) +
					    3600 * perioditem->end_hour;
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

time_t get_end_of_period_for_time_t(const gchar * period, time_t pckt_time)
{
	struct period *pperiod = NULL;
	time_t result = -1;

	g_static_mutex_lock(&period_mutex);
	/* get period in hash */
	pperiod = g_hash_table_lookup(nuauthconf->periods, period);
	if (pperiod == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "period can not be found, typo ?");
		g_static_mutex_unlock(&period_mutex);
		return 0;
	} else {
		GSList *pointer;
		time_t provend;
		/* iter on period_item */
		for (pointer = pperiod->items; pointer;
		     pointer = pointer->next) {
			provend =
			    get_end_of_period_item_for_time((struct
							     period_item
							     *) (pointer->
								 data),
							    pckt_time);
			/* we've got three cases :
			 *  - provend is 0, out of period, we drop
			 *  - provend is -1 (illimited) we do nothing as it is default
			 *  value of result
			 *  - provend is >0 we update result
			 */
			switch (provend) {
			case 0:
				g_static_mutex_unlock(&period_mutex);
				return 0;
			default:	/* here provend is > 0 */
				/* we modify result if and only if previous period items give
				 * drop or if provend is more limitative than current result */
				if ((result == -1) || (provend < result)) {
					result = provend;
				}
			}
		}
	}
	g_static_mutex_unlock(&period_mutex);
	return result;
}

void free_period(gpointer data)
{
	struct period *period = (struct period *) data;
	g_slist_free(period->items);
	g_free(period->description);
	g_free(period->name);
	g_free(period);
}

gboolean delete_period(GHashTable * periods, gchar * name)
{
	return g_hash_table_remove(periods, name);
}


void destroy_periods(GHashTable * periods)
{
	g_hash_table_destroy(periods);
}

gboolean define_new_period(GHashTable * periods, gchar * name,
			   gchar * description)
{
	/* alloc struct */
	struct period *periodelt = g_new0(struct period, 1);
	/* insert in hash */
	periodelt->name = g_strdup(name);
	periodelt->description = g_strdup(description);
	periodelt->items = NULL;
	g_hash_table_insert(periods, g_strdup(name), periodelt);
	return TRUE;
}

gboolean add_perioditem_to_period(GHashTable * periods, gchar * name,
				  struct period_item * perioditem)
{
	/* search entry in hash */
	struct period *periodelt = g_hash_table_lookup(periods, name);
	/* add iperioditem to GSList items (but do sanity check on perioditem) */
	if (periodelt && perioditem) {
		/* set used to TRUE */
		periodelt->items =
		    g_slist_prepend(periodelt->items, perioditem);
		periodelt->used = TRUE;
	} else {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Can not add period item (%p) to period (%s at %p)",
			    perioditem, name, periodelt);
		return FALSE;
	}
	return TRUE;
}

/** can have no parameter as a module reload is needed */
GHashTable *init_periods()
{
	GHashTable *periods = NULL;

	periods = g_hash_table_new_full(g_str_hash,
					g_str_equal,
					g_free,
					(GDestroyNotify) free_period);

	modules_parse_periods(periods);

	return periods;
}

void reload_periods(GHashTable **periods)
{
	g_static_mutex_lock(&period_mutex);
	destroy_periods(*periods);
	*periods = init_periods();
	g_static_mutex_unlock(&period_mutex);
}

/** @} */
