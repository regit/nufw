/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
 **                   INL http://www.inl.fr/
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

/*
 * check_fill_user_counters :
 * Maintain user list and take care of detecting old packets (possibly spoofed)
 * Argument 1 : user id
 * Argument 2 : packet timestamp
 * Argument 3 : IP
 * Return : 1 if OK, 0 otherwise (old packet)
 */

int check_fill_user_counters(u_int16_t userid,long u_time,unsigned long packet_id,u_int32_t ip){
	user_datas * currentuser=NULL;

	currentuser=g_hash_table_lookup(users_hash,(void*)((unsigned long int)userid));
	if (currentuser == NULL){
		/* failure so create user */
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER)) {
			g_message("creating new user %d\n",userid);
		}
		currentuser = g_new0(user_datas,1);
		currentuser->ip=ip;
		currentuser->last_packet_time=u_time;
		currentuser->last_packet_id=packet_id;
		currentuser->last_packet_timestamp=time(NULL);
		currentuser->lock=g_mutex_new();
		g_hash_table_insert(users_hash,(void*)((unsigned long int)userid),currentuser);
		log_new_user(userid,ip);
		return 1;
	} else {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER)) {
			g_message("found user %d\n",userid);
		}
		if ( (u_time < currentuser->last_packet_time) ) {
			/* if packet is older than timeout there can be problem */
			if ( currentuser->last_packet_time - u_time >= packet_timeout) {
				g_warning("Packet for user %d is really too old (timeout is %d)",userid,packet_timeout);
				return 0;
			}
		}
		if (((u_time == currentuser->last_packet_time) && (packet_id <= currentuser->last_packet_id))  ){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER)) {
				g_message("not increasing packet counter for user %d\n",userid);
			}
		} 
		if (g_mutex_trylock(currentuser->lock)){
			currentuser->ip=ip;
			currentuser->last_packet_time=u_time;
			currentuser->last_packet_id=packet_id;
			currentuser->last_packet_timestamp=time(NULL);
			g_mutex_unlock(currentuser->lock);
			/* Vincent moved this after mutex unlock, so the mutex be
			   freed earlier :) */
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)) {
				g_message("updating user %d\n",userid);
			}
		}
		return 1;
	}
	return 0;
}


/*
 * print_id :
 * print id of user (used by print_user_list)
 * Argument 1 : Id of user
 * Argument 2 : Unused
 * Argument 3 : Unused
 * Return : None
 */

void print_id( gpointer id, gpointer value, gpointer user_data) {
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
		g_message("%u ",(unsigned int)id);
}


/*
 * print_users_list :
 * print list of user id
 * Argument : None
 * Return : None
 */

void print_users_list(){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
	{
		g_message("users list : ");
	}
	g_hash_table_foreach(users_hash,(GHFunc)print_id,NULL);
}

/*
 * log_new_user :
 * print log message about new user on IP
 * Argument 1 : user id
 * Argument 2 : ip
 * Return : None
 */

void log_new_user(int id,u_int32_t ip){
	struct in_addr oneip;

	oneip.s_addr=ntohl(ip);
	if ( nuauth_log_users & 1 ){
		g_message("New user with id %d on %s",id,inet_ntoa(oneip));
	}
}

struct Conn_State { 
	connection conn;
	int state;};

/*
 * log_user_packet :
 * log user packet or by a direct call to log module or by sending log 
 * message to logger thread pool
 * Argument 1 : connection
 * Argument 2 : state of the connection
 */

void log_user_packet (connection element,int state){
	struct Conn_State conn_state= { element, state};


	if ((nuauth_log_users_sync) && (state == STATE_OPEN) ){
            if ( nuauth_log_users &  8 ){
		(*module_user_logs) (
				     element, 
				     state
				    );
            }
	} else {
            if (
                ((nuauth_log_users & 2) && (state == STATE_DROP)) 
                || 
                ((nuauth_log_users & 4) && (state == STATE_OPEN)) 
                || 
                (nuauth_log_users & 8) 
               ) {
		/* feed thread pool */
		g_thread_pool_push(user_loggers,
				g_memdup(&conn_state,sizeof(conn_state)),
				NULL);
            }
	}
	/* end */
}


/*
 * real_log_user_packet :
 * interface to logging module function for thread pool worker
 * Argument 1 : struct Conn_State
 * Argument 2 : unused 
 * Return : None
 */

void real_log_user_packet (gpointer userdata, gpointer data){
	(*module_user_logs) (
			     ((struct Conn_State *)userdata)->conn, 
			     ((struct Conn_State *)userdata)->state
			    );
	/* free userdata */
	g_free(userdata);
}
