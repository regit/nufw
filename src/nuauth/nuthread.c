/*
 ** Copyright(C) 2007 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
 **
 ** $Id$
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
#include "nuthread.h"

/**
 * Create one NuAuth thread:
 *   - Create a new mutex (use in thread loop)
 *   - Create the thread with glib.
 *
 * The mutex is used to stop a thread: to stop a thread, just lock its mutex.
 */
void create_thread(struct nuauth_thread_t *thread,
		   const char* name,
		   void *(*func) (GMutex *))
{
	thread->name = name;
	thread->mutex = g_mutex_new();
	thread->thread =
	    g_thread_create((GThreadFunc) func, thread->mutex, TRUE, NULL);
	if (thread->thread == NULL)
		exit(EXIT_FAILURE);
}

/**
 * Wait the end of thread using g_thread_join(). Avoid deadlock: if the
 * active thread is the thread to join, we just skip it.
 */
void wait_thread_end(struct nuauth_thread_t *thread)
{
	GThread *self;
	log_message(DEBUG, DEBUG_AREA_MAIN, "Wait end of thread '%s'", thread->name);
	self = g_thread_self();
	if (self == thread->thread) {
		log_message(INFO, DEBUG_AREA_MAIN,
			    "Information: Avoid deadlock: don't wait end of active thread!");
		return;
	}
	g_thread_join(thread->thread);
}

/**
 * Wait the end of thread using g_thread_join(). Avoid deadlock: if the
 * active thread is the thread to join, we just skip it.
 */
void thread_destroy(struct nuauth_thread_t *thread)
{
	/* make sure that the mutex is unlocked */
	(void)g_mutex_trylock(thread->mutex);
	g_mutex_unlock(thread->mutex);

	/* destroy the mutex */
	g_mutex_free(thread->mutex);
}

