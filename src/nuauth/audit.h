/*
** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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


#ifndef AUDIT_H
#define AUDIT_H

/* AUDIT */

struct audit_struct{
  GThreadPool *users;
  GThreadPool *acls;
  GThreadPool *loggers;
  GHashTable *conn_list;
  GHashTable *aclcache;
  gint cache_req_nb;
  gint cache_hit_nb;
};

struct audit_struct *myaudit;

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);

/* END AUDIT */

#endif
