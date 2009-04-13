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

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <signal.h>

#include "emc_server.h"
#include "emc_config.h"

static struct emc_server_context server_ctx;

int main(int argc, char **argv)
{
	memset(&server_ctx, 0, sizeof(server_ctx));
	nussl_init();

	/* ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	if (emc_init_config(EMC_DEFAULT_CONF) != 0) {
		fprintf(stderr, "ERROR could not load config, aborting\n");
		exit(-1);
	}

	emc_start_server(&server_ctx);

	return 0;
}

