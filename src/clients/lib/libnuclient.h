/*
 ** Copyright 2004-2007 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
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

#ifndef LIBNUCLIENT_H
#define LIBNUCLIENT_H

#include "nufw_source.h"
#include "nuclient.h"

void nu_exit_clean(nuauth_session_t * session);

int compare(nuauth_session_t * session, conntable_t * old, conntable_t * new,
	    nuclient_error * err);

void do_panic(const char *filename, unsigned long line, const char *fmt,
	      ...);

/**
 * \def panic(format, ...)
 *
 * Call do_panic(__FILE__, __LINE__, format, ...)
 */
#define panic(format, args...) \
    do_panic(__FILE__, __LINE__, format, ##args )

/**
 * \def nu_assert(test, format, ...)
 *
 * If test fails, call do_panic(__FILE__, __LINE__, format, ...)
 */
#define nu_assert(test, format, args...) \
    do { if (!(test)) do_panic(__FILE__, __LINE__, format, ##args ); } while (0)

void ask_session_end(nuauth_session_t * session);

#endif
