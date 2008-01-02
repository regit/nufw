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

#include <config.h>
#include "nussl_config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "nussl_alloc.h"

static nussl_oom_callback_fn oom;

void nussl_oom_callback(nussl_oom_callback_fn callback)
{
    oom = callback;
}

#define DO_MALLOC(ptr, len) do {		\
    ptr = malloc((len));			\
    if (!ptr) {					\
	if (oom != NULL)			\
	    oom();				\
	abort();				\
    }						\
} while(0);

void *nussl_malloc(size_t len)
{
    void *ptr;
    DO_MALLOC(ptr, len);
    return ptr;
}

void *nussl_calloc(size_t len)
{
    void *ptr;
    DO_MALLOC(ptr, len);
    return memset(ptr, 0, len);
}

void *nussl_realloc(void *ptr, size_t len)
{
    void *ret = realloc(ptr, len);
    if (!ret) {
	if (oom)
	    oom();
	abort();
    }
    return ret;
}

char *nussl_strdup(const char *s)
{
    char *ret;
    DO_MALLOC(ret, strlen(s) + 1);
    return strcpy(ret, s);
}

char *nussl_strndup(const char *s, size_t n)
{
    char *new;
    DO_MALLOC(new, n+1);
    new[n] = '\0';
    memcpy(new, s, n);
    return new;
}

