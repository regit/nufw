/*
 ** Copyright (C) 2002-2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.com>
 ** INL http://www.inl.fr/
 **
 ** $Id: main.c 3668 2007-08-20 09:55:12Z haypo $
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
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/* 
   Replacement memory allocation handling etc.
   Copyright (C) 1999-2005, Joe Orton <joe@manyfish.co.uk>

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

#ifndef NE_ALLOC_H
#define NE_ALLOC_H

#ifdef WIN32
#include <stdlib.h>
#else
#include <sys/types.h>
#endif

#include "ne_defs.h"

NE_BEGIN_DECLS

typedef void (*ne_oom_callback_fn)(void);

/* Set callback which is called if malloc() returns NULL. */
void ne_oom_callback(ne_oom_callback_fn callback);

#ifndef NEON_MEMLEAK
/* Replacements for standard C library memory allocation functions,
 * which never return NULL. If the C library malloc() returns NULL,
 * neon will abort(); calling an OOM callback beforehand if one is
 * registered.  The C library will only ever return NULL if the
 * operating system does not use optimistic memory allocation. */
void *ne_malloc(size_t size) ne_attribute_malloc;
void *ne_calloc(size_t size) ne_attribute_malloc;
void *ne_realloc(void *ptr, size_t s);
char *ne_strdup(const char *s) ne_attribute_malloc;
char *ne_strndup(const char *s, size_t n) ne_attribute_malloc;
#define ne_free free
#endif

NE_END_DECLS

#endif /* NE_ALLOC_H */
