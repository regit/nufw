/*
** Copyright(C) 2010 EdenWall Technologies
**              Written by Eric Leblond <eleblond@edenwall.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 3 of the License.
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

#include <sys/time.h>


GPrivate *nnd_priv;		/* private pointer to ldap connection */

#define NND_SOCKET_PATH LOCAL_STATE_DIR "/run/nnd.socket"
/* Maximum size of a nnd query */
#define NND_QUERY_SIZE 512

struct nnd_params {
	int nnd_request_timeout;
	char *nnd_socket;
	GPrivate *nnd_priv;
};
