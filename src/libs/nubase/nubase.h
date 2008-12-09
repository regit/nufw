/*
 ** Copyright (C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
 ** INL http://www.inl.fr/
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


#ifndef NUBASE_HEADER
#define NUBASE_HEADER

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif

#include <limits.h>

#include "config-table.h"
#include "ipv6.h"
#include "log.h"
#include "packet_parser.h"
#include "strings.h"

typedef enum {
	NU_EXIT_ERROR = -1,
	NU_EXIT_OK = 0,
	NU_EXIT_NO_RETURN,
	NU_EXIT_CONTINUE
} nu_error_t;


#endif				/* ifndef NUBASE_HEADER */
