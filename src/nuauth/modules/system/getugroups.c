/* getugroups.c -- return a list of the groups a user is in

   Modified for NuFW by Eric Leblond <regit@inl.fr>

   Copyright (C) 1990, 1991, 1998, 1999, 2000, 2003 Free Software Foundation.

   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Written by David MacKenzie. */

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
#include <stdio.h> /* grp.h on alpha OSF1 V2.0 uses "FILE *". */

#include <grp.h>
#define BUFLEN 4096
#define MAXCOUNT 128

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* setgrent, getgrent, and endgrent are not specified by POSIX.1,
   so header files might not declare them.
   If you don't have them at all, we can't implement this function.
   You lose!  */
struct group *getgrent ();

#include <string.h>

GStaticMutex group_mutex;

/**
 * \brief Get list of group a user belong to
 *
 * Like `getgroups', but for user USERNAME instead of for the current
   process.  Store at most MAXCOUNT group IDs in the GROUPLIST array.
   If GID is not -1, store it first (if possible).  GID should be the
   group ID (pw_gid) obtained from getpwuid, in case USERNAME is not
   listed in /etc/groups.
   Always return the number of groups of which USERNAME is a member.

   \param username String containing the username
   \param gid This is the primary group of the user
   \return A list of group under the form of a GSList
 */

  GSList *
getugroups (char *username, gid_t gid)
{
  struct group *grp;
  register char **cp;
  register int count = 0;
  GSList* grouplist=NULL;

  if (gid != (gid_t) -1)
  {
      grouplist = g_slist_prepend(grouplist,GINT_TO_POINTER(gid));
  }

  /* need to lock as position is common to all thread */
  g_static_mutex_lock(&group_mutex);

  setgrent ();
  while ((grp = getgrent ()) != 0){
      for (cp = grp->gr_mem; *cp; ++cp) {
          GSList * item;

          if ( strcmp(username, *cp))
              continue;

          /* See if this group number is already on the list.  */
          for (item = grouplist; item ; item=item->next){
              if (grouplist && (gid_t)GPOINTER_TO_INT(grouplist->data) == grp->gr_gid){
                  break;
              }
          }

          grouplist = g_slist_prepend(grouplist,GINT_TO_POINTER(grp->gr_gid));
          /* If it's a new group number, then try to add it to the list.  */
      }
      count++;
      if (count > MAXCOUNT){
        endgrent();
        g_static_mutex_unlock (&group_mutex);
        return grouplist;
      }
  }
  endgrent ();

  /* release lock */
  g_static_mutex_unlock (&group_mutex);

  return grouplist;
}

/**
 * @}
 */
