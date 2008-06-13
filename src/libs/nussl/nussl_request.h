/*
   HTTP Request Handling
   Copyright (C) 1999-2006, Joe Orton <joe@manyfish.co.uk>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#ifndef NUSSL_REQUEST_H
#define NUSSL_REQUEST_H

#include <config.h>
#include "nussl_config.h"
#include "nussl_session.h"


NUSSL_BEGIN_DECLS
#define NUSSL_OK (0)		/* Success */
#define NUSSL_ERROR (1)		/* Generic error; use nussl_get_error(session) for message */
#define NUSSL_LOOKUP (2)	/* Server or proxy hostname lookup failed */
#define NUSSL_AUTH (3)		/* User authentication failed on server */
#define NUSSL_PROXYAUTH (4)	/* User authentication failed on proxy */
#define NUSSL_CONNECT (5)	/* Could not connect to server */
#define NUSSL_TIMEOUT (6)	/* Connection timed out */
#define NUSSL_FAILED (7)	/* The precondition failed */
#define NUSSL_RETRY (8)		/* Retry request (nussl_end_request ONLY) */
#define NUSSL_REDIRECT (9)	/* See nussl_redirect.h */
int nussl_open_connection(nussl_session * sess);

NUSSL_END_DECLS
#endif				/* NUSSL_REQUEST_H */
