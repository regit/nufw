/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
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

#ifndef __EMC_SERVER_H__
#define __EMC_SERVER_H__

#include <config.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include <nussl.h>

struct emc_server_context {
	int continue_processing;
	int server_sock;

	nussl_session *nussl;
};

struct emc_client_context {
	nussl_session *nussl;
};

int emc_start_server(struct emc_server_context *ctx);

#endif /* __EMC_SERVER_H__ */
