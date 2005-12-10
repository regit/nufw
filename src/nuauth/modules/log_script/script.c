/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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
#include <string.h>
#include <errno.h>

G_MODULE_EXPORT int user_session_logs(user_session *c_session,int state)
{
	struct in_addr remote_inaddr;
	remote_inaddr.s_addr=c_session->addr;
	char addresse[INET_ADDRSTRLEN+1];
	char cmdbuffer[128];
        
        inet_ntop( AF_INET, &remote_inaddr, addresse, INET_ADDRSTRLEN);
        switch (state) {
          case SESSION_OPEN:
		snprintf(cmdbuffer,128,CONFIG_DIR "/user-up.sh %s %s",c_session->userid,addresse);
                break;
          case SESSION_CLOSE:
		snprintf(cmdbuffer,128,CONFIG_DIR "/user-down.sh %s %s",c_session->userid,addresse);
                break;
        }
	system(cmdbuffer);
        return 1;
}

