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

#include "nussl_config.h"

#include <sys/types.h>

#include <string.h>

#include <stdio.h>
#include <ctype.h> /* isdigit() for ne_parse_statusline */

#ifdef NE_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/opensslv.h>
#endif

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

/* libxml2: pick up the version string. */
#if defined(HAVE_LIBXML)
#include <libxml/xmlversion.h>
#elif defined(HAVE_EXPAT) && !defined(HAVE_XMLPARSE_H)
#include <expat.h>
#endif

#include "nussl_utils.h"
#include "nussl_string.h" /* for ne_strdup */
#include "nussl_dates.h"

int ne_debug_mask = 0;
FILE *ne_debug_stream = NULL;

void ne_debug_init(FILE *stream, int mask)
{
    ne_debug_stream = stream;
    ne_debug_mask = mask;
#if defined(HAVE_SETVBUF) && defined(_IONBF)
    /* If possible, turn off buffering on the debug log.  this is very
     * helpful if debugging segfaults. */
    if (stream) setvbuf(stream, NULL, _IONBF, 0);
#endif        
}

void ne_debug(int ch, const char *template, ...) 
{
    va_list params;
    if ((ch & ne_debug_mask) == 0) return;
    fflush(stdout);
    va_start(params, template);
    vfprintf(ne_debug_stream, template, params);
    va_end(params);
/*    if ((ch & NE_DBG_FLUSH) == NE_DBG_FLUSH)
	fflush(ne_debug_stream);*/
}

#define NE_STRINGIFY(x) # x
#define NE_EXPAT_VER(x,y,z) NE_STRINGIFY(x) "." NE_STRINGIFY(y) "." NE_STRINGIFY(z)

static const char version_string[] = "neon " NEON_VERSION ": " 
#ifdef NEON_IS_LIBRARY
  "Library build"
#else
  "Bundled build"
#endif
#ifdef NE_HAVE_IPV6
   ", IPv6"
#endif
#ifdef HAVE_EXPAT
  ", Expat"
/* expat >=1.95.2 exported the version */
#ifdef XML_MAJOR_VERSION
" " NE_EXPAT_VER(XML_MAJOR_VERSION, XML_MINOR_VERSION, XML_MICRO_VERSION)
#endif
#else /* !HAVE_EXPAT */
#ifdef HAVE_LIBXML
  ", libxml " LIBXML_DOTTED_VERSION
#endif /* HAVE_LIBXML */
#endif /* !HAVE_EXPAT */
#if defined(NE_HAVE_ZLIB) && defined(ZLIB_VERSION)
  ", zlib " ZLIB_VERSION
#endif /* NE_HAVE_ZLIB && ... */
#ifdef NE_HAVE_SOCKS
   ", SOCKSv5"
#endif
#ifdef HAVE_OPENSSL
#ifdef OPENSSL_VERSION_TEXT
    ", " OPENSSL_VERSION_TEXT
#else
   "OpenSSL (unknown version)"
#endif /* OPENSSL_VERSION_TEXT */
#endif /* HAVE_OPENSSL */
#ifdef HAVE_GNUTLS
    ", GNU TLS " LIBGNUTLS_VERSION
#endif /* HAVE_GNUTLS */
   "."
;

const char *ne_version_string(void)
{
    return version_string;
}

int ne_version_match(int major, int minor)
{
    return NE_VERSION_MAJOR != major || NE_VERSION_MINOR < minor
        || (NE_VERSION_MAJOR == 0 && NE_VERSION_MINOR != minor);
}

int ne_has_support(int feature)
{
    switch (feature) {
#if defined(NE_HAVE_SSL) || defined(NE_HAVE_ZLIB) || defined(NE_HAVE_IPV6) \
    || defined(NE_HAVE_SOCKS) || defined(NE_HAVE_LFS) \
    || defined(NE_HAVE_TS_SSL) || defined(NE_HAVE_I18N)
#ifdef NE_HAVE_SSL
    case NE_FEATURE_SSL:
#endif
#ifdef NE_HAVE_ZLIB
    case NE_FEATURE_ZLIB:
#endif
#ifdef NE_HAVE_IPV6
    case NE_FEATURE_IPV6:
#endif
#ifdef NE_HAVE_SOCKS
    case NE_FEATURE_SOCKS:
#endif
#ifdef NE_HAVE_LFS
    case NE_FEATURE_LFS:
#endif
#ifdef NE_HAVE_TS_SSL
    case NE_FEATURE_TS_SSL:
#endif
#ifdef NE_HAVE_I18N
    case NE_FEATURE_I18N:
#endif
        return 1;
#endif /* NE_HAVE_* */
    default:
        return 0;
    }
}
