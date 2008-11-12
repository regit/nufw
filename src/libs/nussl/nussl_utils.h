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
   HTTP utility functions
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

#ifndef NUSSL_UTILS_H
#define NUSSL_UTILS_H

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>

#include "nussl_config.h"
#include "nussl_constants.h"
#include "nussl_defs.h"

#ifdef NEON_TRIO
#include <trio.h>
#endif

NUSSL_BEGIN_DECLS
/* Returns a human-readable library version string describing the
 * version and build information; for example:
 *    "neon 0.2.0: Library build, OpenSSL support" */
const char *nussl_version_string(void);

/* Returns non-zero if library version is not of major version
 * 'major', or if minor version is not greater than or equal to
 * 'minor'.  For neon versions with major == 0, all minor versions are
 * presumed to be incompatible.  */
int nussl_version_match(int major, int minor);

/* Feature codes: */
#define NUSSL_FEATURE_SSL (1)	/* SSL/TLS support */
#define NUSSL_FEATURE_ZLIB (2)	/* zlib compression in compress interface */
#define NUSSL_FEATURE_IPV6 (3)	/* IPv6 is supported in resolver */
#define NUSSL_FEATURE_LFS (4)	/* large file support */
#define NUSSL_FEATURE_SOCKS (5)	/* SOCKSv5 support */
#define NUSSL_FEATURE_TS_SSL (6)	/* Thread-safe SSL/TLS support */
#define NUSSL_FEATURE_I18N (7)	/* i18n error message support */

/* Returns non-zero if library is built with support for the given
 * NUSSL_FEATURE_* feature code 'code'. */
int nussl_has_support(int feature);

/* Debugging macro to allow code to be optimized out if debugging is
 * disabled at build time. */
#if 0
#ifndef NUSSL_DEBUGGING
#define NUSSL_DEBUG if (0) nussl_debug
#else				/* DEBUGGING */
#define NUSSL_DEBUG nussl_debug
#endif				/* DEBUGGING */
#endif



/* Debugging masks. */
#if 0
#define NUSSL_DBG_SOCKET (1<<0)	/* raw socket */
#define NUSSL_DBG_HTTP (1<<1)	/* HTTP request/response handling */
#define NUSSL_DBG_XML (1<<2)	/* XML parser */
#define NUSSL_DBG_HTTPAUTH (1<<3)	/* HTTP authentication (hiding credentials) */
#define NUSSL_DBG_HTTPPLAIN (1<<4)	/* plaintext HTTP authentication */
#define NUSSL_DBG_LOCKS (1<<5)	/* WebDAV locking */
#define NUSSL_DBG_XMLPARSE (1<<6)	/* low-level XML parser */
#define NUSSL_DBG_HTTPBODY (1<<7)	/* HTTP response body blocks */
#define NUSSL_DBG_SSL (1<<8)	/* SSL/TLS */
#define NUSSL_DBG_FLUSH (1<<30)	/* always flush debugging */
#endif

#define NUSSL_DEBUG fprintf

#define NUSSL_DBG_SOCKET stderr
#define NUSSL_DBG_HTTP stderr
#define NUSSL_DBG_XML stderr
#define NUSSL_DBG_HTTPAUTH stderr
#define NUSSL_DBG_HTTPPLAIN stderr
#define NUSSL_DBG_LOCKS stderr
#define NUSSL_DBG_XMLPARSE stderr
#define NUSSL_DBG_HTTPBODY stderr
#define NUSSL_DBG_SSL stderr
#define NUSSL_DBG_FLUSH stderr



/* Send debugging output to 'stream', for all of the given debug
 * channels.  To disable debugging, pass 'stream' as NULL and 'mask'
 * as 0. */
void nussl_debug_init(FILE * stream, int mask);

/* The current debug mask and stream set by the last call to
 * nussl_debug_init. */
extern int nussl_debug_mask;
extern FILE *nussl_debug_stream;

/* Produce debug output if any of channels 'ch' is enabled for
 * debugging. */
void nussl_debug(int ch, const char *,
		 ...) nussl_attribute((format(printf, 2, 3)));

/* Storing an HTTP status result */
typedef struct {
	int major_version;
	int minor_version;
	int code;		/* Status-Code value */
	int klass;		/* Class of Status-Code (1-5) */
	char *reason_phrase;
} nussl_status;

/* NB: couldn't use 'class' in nussl_status because it would clash with
 * the C++ reserved word. */

int check_key_perms(const char *filename);

NUSSL_END_DECLS
#endif				/* NUSSL_UTILS_H */
