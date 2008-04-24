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
   Standard definitions for neon headers
   Copyright (C) 2003-2006, Joe Orton <joe@manyfish.co.uk>

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

#undef NUSSL_BEGIN_DECLS
#undef NUSSL_END_DECLS
#ifdef __cplusplus
# define NUSSL_BEGIN_DECLS extern "C" {
# define NUSSL_END_DECLS }
#else
# define NUSSL_BEGIN_DECLS	/* empty */
# define NUSSL_END_DECLS	/* empty */
#endif

#ifndef NUSSL_DEFS_H
#define NUSSL_DEFS_H

#include <sys/types.h>

#ifdef NUSSL_LFS
typedef off64_t nussl_off_t;
#else
typedef off_t nussl_off_t;
#endif

/* define ssize_t for Win32 */
#if defined(WIN32) && !defined(ssize_t)
#define ssize_t int
#endif

#ifdef __GNUC__
#if __GNUC__ >= 3
#define nussl_attribute_malloc __attribute__((malloc))
#else
#define nussl_attribute_malloc
#endif
#define nussl_attribute(x) __attribute__(x)
#else
#define nussl_attribute(x)
#define nussl_attribute_malloc
#endif

#ifndef NUSSL_BUFSIZ
#define NUSSL_BUFSIZ 8192
#endif

#endif				/* NUSSL_DEFS_H */
