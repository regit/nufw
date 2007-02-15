/*
 ** Copyright(C) 2004-2007 INL
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
#include "command.h"
#include <sys/un.h> /* unix socket */

#define SOCKET_FILENAME "/tmp/nuauth-command.socket"

typedef struct {
    int socket;
    int client;
    struct sockaddr_un client_addr;
    int select_max;
    fd_set select_set;
} command_t;

int command_new(command_t *cmd)
{
    struct sockaddr_un addr;
    int len;
    int res;
    int on = 1;

    cmd->socket = -1;
    cmd->client = -1;
    cmd->select_max = 0;

    /* set address */
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_FILENAME, sizeof(addr.sun_path));
    addr.sun_path[sizeof(addr.sun_path)-1] = 0;
    len = strlen(addr.sun_path) + sizeof(addr.sun_family);

    /* create socket */
    cmd->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cmd->socket == -1) {
        log_message(CRITICAL, AREA_MAIN,
            "Command server: enable to create UNIX socket %s: %s",
            addr.sun_path, g_strerror(errno));
        return 0;
    }
    cmd->select_max = cmd->socket + 1;

    /* set reuse option */
    res = setsockopt(cmd->socket, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on));

    /* bind socket */
    res = bind(cmd->socket, (struct sockaddr *)&addr, len);
    if (res == -1) {
        log_message(CRITICAL, AREA_MAIN,
            "Command server: UNIX socket bind() error: %s",
            g_strerror(errno));
        return 0;
    }

    /* listen */
    if (listen(cmd->socket, 1) == -1) {
        log_message(CRITICAL, AREA_MAIN,
            "Command server: UNIX socket listen() error: %s",
            g_strerror(errno));
        return 0;
    }
    return 1;
}

int command_client_accept(command_t *cmd)
{
    socklen_t len = sizeof(cmd->client_addr);

    cmd->client = accept(cmd->socket, (struct sockaddr *)&cmd->client_addr, &len);
    if (cmd->client < 0)
    {
        log_message(CRITICAL, AREA_MAIN,
            "Command server: accept() error: %s", g_strerror(errno));
        return 0;
    }
    if (cmd->socket < cmd->client)
        cmd->select_max = cmd->client + 1;
    else
        cmd->select_max = cmd->socket + 1;
    return 1;
}

void command_client_close(command_t *cmd)
{
    close(cmd->client);
    cmd->client = -1;
    cmd->select_max = cmd->socket + 1;
}

int command_main(command_t *cmd)
{
    struct timeval tv;
    int ret;

    /* Wait activity on the socket */
    FD_ZERO(&cmd->select_set);
    FD_SET(cmd->socket, &cmd->select_set);
    if (0 <= cmd->client)
        FD_SET(cmd->client, &cmd->select_set);
    tv.tv_sec=1;
    tv.tv_usec=0;
    ret = select(cmd->select_max, &cmd->select_set, NULL, NULL, &tv);

    /* catch select() error */
    if (ret == -1) {
        /* Signal was catched: just ignore it */
        if (errno == EINTR)
        {
            return 1;
        }

        log_message(CRITICAL, AREA_MAIN,
                "Command server: select() fatal error: %s",
                g_strerror(errno));
        return 0;
    }

    /* timeout: continue */
    if (ret == 0) {
        return 1;
    }

    if (FD_ISSET(cmd->socket, &cmd->select_set))
    {
        if (!command_client_accept(cmd))
            return 0;
        command_client_close(cmd);
    }
    return 1;
}

void* command_server(GMutex* mutex)
{
    command_t command;

    if (!command_new(&command))
        return NULL;

    while (g_mutex_trylock(mutex))
    {
        g_mutex_unlock(mutex);

        command_main(&command);
    }
    return NULL;
}

