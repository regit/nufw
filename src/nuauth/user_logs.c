
/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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
#include <time.h>

int check_fill_user_counters(u_int16_t userid,long u_time,unsigned long packet_id,u_int32_t ip){
	user_datas * currentuser=NULL;
	/* lookup users */
	if (debug) {
		printf("%d : looking for %d\n",getpid(),userid);
	}
	currentuser=g_hash_table_lookup(users_hash,userid);
	if (currentuser == NULL){
		/* failure so create user */
		if (debug) {
			printf("%d : creating new user %d\n",getpid(),userid);
		}
		currentuser = g_new0(user_datas,1);
		currentuser->ip=ip;
		currentuser->last_packet_time=u_time;
		currentuser->last_packet_id=packet_id;
		currentuser->last_packet_timestamp=time(NULL);
		currentuser->lock=g_mutex_new();
		g_hash_table_insert(users_hash,userid,currentuser);
		if (debug) {
			printf("%d : new user %d\n",getpid(),userid);
		}
		return 1;
	} else {
		if (debug) {
			printf("%d : found user %d\n",getpid(),userid);
		}
		if ( (u_time < currentuser->last_packet_time) || ((u_time == currentuser->last_packet_time) && (packet_id <= currentuser->last_packet_id))  ){
			return 0;
		} else {
			if (g_mutex_trylock(currentuser->lock)){
				currentuser->ip=ip;
				currentuser->last_packet_time=u_time;
				currentuser->last_packet_id=packet_id;
				currentuser->last_packet_timestamp=time(NULL);
				g_mutex_unlock(currentuser->lock);
			}
			return 1;
		}
	}
	
	return 0;
}

void print_id( gpointer id, gpointer value, gpointer user_data) {
	printf("%u ",id);
}

void print_users_list(){
	printf("users list : ");
  	g_hash_table_foreach(users_hash,(GHFunc)print_id,NULL);
  	printf(".\n");
}
