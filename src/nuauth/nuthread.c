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

#include "auth_srv.h"
#include "nuthread.h"

/**
 * Create one NuAuth thread:
 *   - Create a new mutex (use in thread loop)
 *   - Create the thread with glib.
 *
 * The mutex is used to stop a thread: to stop a thread, just lock its mutex.
 */
void thread_new(struct nuauth_thread_t *thread,
		const char* name,
		void *(*func) (GMutex *))
{
	thread->name = name;
	thread->mutex = g_mutex_new();
	thread->thread =
	    g_thread_create((GThreadFunc) func, thread->mutex, TRUE, NULL);
	if (thread->thread == NULL)
	{
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "FATAL ERROR: Unable to create thread %s!",
			    name);
		exit(EXIT_FAILURE);
	}
	thread->valid = 1;
}

void thread_new_wdata(struct nuauth_thread_t *thread,
		const char* name,
		gpointer data,
		void *(*func) (struct nuauth_thread_t *))
{
	thread->name = name;
	thread->mutex = g_mutex_new();
	thread->data = data;
	thread->thread =
	    g_thread_create((GThreadFunc) func, thread , TRUE, NULL);
	if (thread->thread == NULL)
	{
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "FATAL ERROR: Unable to create thread %s!",
			    name);
		exit(EXIT_FAILURE);
	}
	thread->valid = 1;
}

/**
 * Stop a thread: lock its mutex to ask it to leave.
 */
void thread_stop(struct nuauth_thread_t *thread)
{
	if (!thread->valid)
		return;
	(void)g_mutex_trylock(thread->mutex);
}

void thread_list_stop(GSList *thread_list)
{
	GSList *thread_p = thread_list;
	while (thread_p) {
		thread_stop((struct nuauth_thread_t *)thread_p->data);
		thread_p = thread_p->next;
	}
	return;
}

void thread_list_stop_user_ev(GSList *thread_list)
{
	GSList *thread_p = thread_list;
	struct tls_user_context_t *context;
	while (thread_p) {
		context = (struct tls_user_context_t *)((struct nuauth_thread_t *)thread_p->data)->data;
		if (context->loop) {
			ev_async_send(context->loop, &context->loop_fini_signal);
		}
		thread_p = thread_p->next;
	}
	return;
}

void thread_list_stop_nufw_ev(GSList *thread_list)
{
	GSList *thread_p = thread_list;
	struct tls_nufw_context_t *context;
	while (thread_p) {
		context = (struct tls_nufw_context_t *)((struct nuauth_thread_t *)thread_p->data)->data;
		if (context->loop) {
			ev_async_send(context->loop, &context->loop_fini_signal);
		}
		thread_p = thread_p->next;
	}
	return;
}

/**
 * Wait the end of thread using g_thread_join(). Avoid deadlock: if the
 * active thread is the thread to join, we just skip it.
 */
void thread_wait_end(struct nuauth_thread_t *thread)
{
	GThread *self;
	if (!thread->valid)
		return;
	log_message(DEBUG, DEBUG_AREA_MAIN, "Wait end of thread '%s'", thread->name);
	self = g_thread_self();
	if (self == thread->thread) {
		log_message(INFO, DEBUG_AREA_MAIN,
			    "Information: Avoid deadlock: don't wait end of active thread!");
		return;
	}
	g_thread_join(thread->thread);
}

void thread_list_wait_end(GSList *thread_list)
{
	GSList *thread_p = thread_list;
	while (thread_p) {
		thread_wait_end((struct nuauth_thread_t *)thread_p->data);
		thread_p = thread_p->next;
	}
	return;
}

/**
 * Wait the end of thread using g_thread_join(). Avoid deadlock: if the
 * active thread is the thread to join, we just skip it.
 */
void thread_destroy(struct nuauth_thread_t *thread)
{
	if (!thread->valid)
		return;
	/* make sure that the mutex is unlocked */
	(void)g_mutex_trylock(thread->mutex);
	g_mutex_unlock(thread->mutex);

	/* destroy the mutex */
	g_mutex_free(thread->mutex);
	thread->valid = 0;
}

void thread_list_destroy(GSList *thread_list)
{
	GSList *thread_p = thread_list;
	while (thread_p) {
		thread_destroy((struct nuauth_thread_t *)thread_p->data);
		thread_p = thread_p->next;
	}
	return;
}

