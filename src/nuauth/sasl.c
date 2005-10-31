/*
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

#include <auth_srv.h>

/*sasl init function*/
void *sasl_gthread_mutex_init(void)
{
	GMutex* lock = g_mutex_new();
	if (!lock)								      
		return NULL;							      
	return lock;
}

int sasl_gthread_mutex_lock(void *lock)
{
	g_mutex_lock(lock);
	return 0;
}

int sasl_gthread_mutex_unlock(void *lock)
{
	g_mutex_unlock(lock);
	return 0;
}

void sasl_gthread_mutex_free(void *lock)
{
	g_mutex_free(lock);
}

void our_sasl_init(void){
	sasl_set_mutex(sasl_gthread_mutex_init, 
			sasl_gthread_mutex_lock, 
			sasl_gthread_mutex_unlock, 
			sasl_gthread_mutex_free);
}



