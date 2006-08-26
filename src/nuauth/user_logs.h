/*
 ** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
 **                  INL http://www.inl.fr/
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

#ifndef USER_LOGS_H
#define USER_LOGS_H

typedef enum {
    SESSION_CLOSE=0,
    SESSION_OPEN     /* =1 */
} session_state_t;    

struct session_event {
	user_session_t* session;
	session_state_t state;
};
 
int check_fill_user_counters(u_int16_t userid,long time,unsigned long packet_id,u_int32_t ip);
void print_users_list();

void log_user_packet (connection_t* element, tcp_state_t state);
void log_user_packet_from_tracking_t(tracking_t* datas,tcp_state_t pstate);

void real_log_user_packet (gpointer userdata, gpointer data);

void log_user_packet_from_accounted_connection(struct accounted_connection* datas,tcp_state_t state);

void log_user_session(user_session_t* element, session_state_t state);
void log_user_session_thread (gpointer element,gpointer state);

#endif
