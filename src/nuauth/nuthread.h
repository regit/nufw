/*
 ** Copyright(C) 2007 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
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

#ifndef NUTHREAD_H
#define NUTHREAD_H

struct nuauth_thread_t {
	int valid;
	GThread *thread;
	GMutex *mutex;
	const char *name;
	gpointer data;
};

void thread_new(struct nuauth_thread_t *thread,
		const char* name,
		void *(*func) (GMutex *));
void thread_new_wdata(struct nuauth_thread_t *thread,
		const char* name,
		gpointer data,
		void *(*func) (struct nuauth_thread_t *));
void thread_stop(struct nuauth_thread_t *thread);
void thread_list_stop(GSList *thread_list);
void thread_wait_end(struct nuauth_thread_t *thread);
void thread_list_wait_end(GSList *thread_list);
void thread_destroy(struct nuauth_thread_t *thread);
void thread_list_destroy(GSList *thread_list);

#endif

