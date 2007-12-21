/*
   HTTP Request Handling
   Copyright (C) 1999-2006, Joe Orton <joe@manyfish.co.uk>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#ifndef NE_REQUEST_H
#define NE_REQUEST_H

#include <config.h>
#include "nussl_config.h"
#include "nussl_session.h"


NE_BEGIN_DECLS

#define NE_OK (0) /* Success */
#define NE_ERROR (1) /* Generic error; use ne_get_error(session) for message */
#define NE_LOOKUP (2) /* Server or proxy hostname lookup failed */
#define NE_AUTH (3) /* User authentication failed on server */
#define NE_PROXYAUTH (4) /* User authentication failed on proxy */
#define NE_CONNECT (5) /* Could not connect to server */
#define NE_TIMEOUT (6) /* Connection timed out */
#define NE_FAILED (7) /* The precondition failed */
#define NE_RETRY (8) /* Retry request (ne_end_request ONLY) */
#define NE_REDIRECT (9) /* See ne_redirect.h */

int ne_open_connection(ne_session* sess);

NE_END_DECLS

#endif /* NE_REQUEST_H */
