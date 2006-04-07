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

G_MODULE_EXPORT int user_session_logs(user_session_t *c_session, session_state_t state,gpointer params)
{
	struct in_addr remote_inaddr;
	remote_inaddr.s_addr=c_session->addr;
	char address[INET_ADDRSTRLEN+1];
	char cmdbuffer[200];
    char *quoted_username = g_shell_quote(c_session->user_name);
    char *quoted_address;
    char *format;
    gboolean ok;
    
    const char *err = inet_ntop( AF_INET, &remote_inaddr, address, INET_ADDRSTRLEN);
    if (err == NULL) {
        return -1;
    }
    quoted_address = g_shell_quote(address);

    if (state == SESSION_OPEN) {
        format = CONFIG_DIR "/user-up.sh %s %s";
    } else { /* state == SESSION_CLOSE */
        format = CONFIG_DIR "/user-down.sh %s %s";
    }
    ok = secure_snprintf(cmdbuffer, sizeof(cmdbuffer), format, quoted_username,quoted_address);
    if (ok) {
        system(cmdbuffer);
    } else {
        log_message(WARNING, AREA_MAIN, "Can't call script, command line truncated!");
    }
    g_free(quoted_username);
    g_free(quoted_address);
    return 1;
}


G_MODULE_EXPORT gboolean module_params_unload(gpointer params_p)
{
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  return TRUE;
}
