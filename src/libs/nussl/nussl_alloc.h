/*
 ** Copyright (C) 2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/*
   Replacement memory allocation handling etc.
   Copyright (C) 1999-2005, Joe Orton <joe@manyfish.co.uk>

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

#ifndef NUSSL_ALLOC_H
#define NUSSL_ALLOC_H

#ifdef WIN32
#include <stdlib.h>
#else
#include <sys/types.h>
#endif

#include "nussl_defs.h"

NUSSL_BEGIN_DECLS typedef void (*nussl_oom_callback_fn) (void);

/* Set callback which is called if malloc() returns NULL. */
void nussl_oom_callback(nussl_oom_callback_fn callback);

#ifndef NEON_MEMLEAK
/* Replacements for standard C library memory allocation functions,
 * which never return NULL. If the C library malloc() returns NULL,
 * neon will abort(); calling an OOM callback beforehand if one is
 * registered.  The C library will only ever return NULL if the
 * operating system does not use optimistic memory allocation. */
void *nussl_malloc(size_t size) nussl_attribute_malloc;
void *nussl_calloc(size_t size) nussl_attribute_malloc;
void *nussl_realloc(void *ptr, size_t s);
char *nussl_strdup(const char *s) nussl_attribute_malloc;
char *nussl_strndup(const char *s, size_t n) nussl_attribute_malloc;
#define nussl_free free
#endif

NUSSL_END_DECLS
#endif				/* NUSSL_ALLOC_H */
