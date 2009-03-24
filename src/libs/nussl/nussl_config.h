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


/*                                                      -*- c -*-
   Win32 config.h
   Copyright (C) 1999-2000, Peter Boos <pedib@colorfullife.com>
   Copyright (C) 2002-2006, Joe Orton <joe@manyfish.co.uk>

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
#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

/* #define NUSSL_DBG_SSL fprintf */

#define  HAVE_FNCTL

#define NEON_VERSION "NuNeon"

/*#define NUSSL_USE_POLL 1 XXX: remove anything related to me*/
#define NUSSL_VERSION_MAJOR 0
#define NUSSL_VERSION_MINOR 1

#define HAVE_SIGNAL_H
#define HAVE_SIGNAL

#define NUSSL_HAVE_TS_SSL	/* TS = Thread Safe */
/* #define HAVE_OPENSSL */

#define NUSSL_FMT_SIZE_T "u"
#define NUSSL_FMT_SSIZE_T "d"
#define NUSSL_FMT_OFF_T "ld"
#define NUSSL_FMT_NE_OFF_T NUSSL_FMT_OFF_T

#ifndef NUSSL_FMT_XML_SIZE
#define NUSSL_FMT_XML_SIZE "d"
#endif

/* needs adjusting for Win64... */
#define SIZEOF_INT 4
#define SIZEOF_LONG 4

#ifdef WIN32

#define HAVE_SETSOCKOPT

//#define HAVE_SSPI
#undef NUSSL_HAVE_TS_SSL

/* Define to enable debugging */
#define NUSSL_DEBUGGING 1

#define SHUT_RDWR SD_BOTH
#include <winsock2.h>

#if 0
/* Win32 uses a underscore, so we use a macro to eliminate that. */
#define snprintf			_snprintf
#define vsnprintf			_vsnprintf
#if defined(_MSC_VER) && _MSC_VER >= 1400
#define strcasecmp			_strcmpi
#define strncasecmp			_strnicmp
#else
#define strcasecmp			strcmpi
#define strncasecmp			strnicmp
#endif
#define ssize_t				int
#define inline                          __inline
#define off_t                           _off_t
#endif /* 0 */

#ifndef USE_GETADDRINFO
#define in_addr_t                       unsigned int
#endif

#define socklen_t                       int

#include <io.h>
#define read _read

#endif
