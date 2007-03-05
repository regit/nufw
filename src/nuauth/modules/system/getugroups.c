/* getugroups.c -- return a list of the groups a user is in

   Copyright (C) 2007 INL
   Written by Eric Leblond <regit@inl.fr>

   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the license.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/**
 * \ingroup SystemModule
 * @{
 */

/**
 * \file getugroups.c
 *
 * \brief Contains getugroups() which is used to retrieve user's group
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "auth_srv.h"

#include <sys/types.h>
#include <stdio.h>		/* grp.h on alpha OSF1 V2.0 uses "FILE *". */

#include <grp.h>
#define BUFLEN 4096

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <string.h>

GStaticMutex group_mutex;

gint system_glibc_cant_guess_maxgroups;

/**
 * \brief Get list of group a user belong to
 *
 * Like `getgroups', but for user USERNAME instead of for the current
   process. If GID is not -1, store it first (if possible).  GID should be the
   group ID (pw_gid) obtained from getpwuid, in case USERNAME is not
   listed in /etc/groups.
   Always return the number of groups of which USERNAME is a member.

   \param username String containing the username
   \param gid This is the primary group of the user
   \return A list of group under the form of a GSList
 */

GSList *getugroups(char *username, gid_t gid)
{
	GSList *grouplist = NULL;
	int i, ng = 0;
	gid_t *groups = NULL;

	/* need to lock as position is common to all thread */
	g_static_mutex_lock(&group_mutex);

#ifdef PERF_DISPLAY_ENABLE
	{
		struct timeval tvstart, tvend, result;
		gettimeofday(&tvstart, NULL);
#endif
		if (system_glibc_cant_guess_maxgroups) {
			ng = system_glibc_cant_guess_maxgroups;
		} else {
			if (getgrouplist(username, gid, NULL, &ng) >= 0) {
				return NULL;
			}
		}

		groups = g_new0(gid_t, ng);
		getgrouplist(username, gid, groups, &ng);

		for (i = 0; i < ng; i++) {
			grouplist =
			    g_slist_prepend(grouplist,
					    GINT_TO_POINTER(groups[i]));
		}

		g_free(groups);

#ifdef PERF_DISPLAY_ENABLE
		gettimeofday(&tvend, NULL);
		timeval_substract(&result, &tvend, &tvstart);
		log_message(INFO, DEBUG_AREA_MAIN,
			    "Group list fetching duration: %ld sec %03ld msec",
			    result.tv_sec, result.tv_usec / 1000);
	}
#endif

	/* release lock */
	g_static_mutex_unlock(&group_mutex);

	return grouplist;
}

/**
 * @}
 */
