/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
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

   In addition, as a special exception, INL
   gives permission to link the code of its release of NuSSL with the
   OpenSSL project's "OpenSSL" library (or with modified versions of it
   that use the same license as the "OpenSSL" library), and distribute
   the linked executables.  You must obey the GNU General Public License
   in all respects for all of the code used other than "OpenSSL".  If you
   modify this file, you may extend this exception to your version of the
   file, but you are not obligated to do so.  If you do not wish to do
   so, delete this exception statement from your version.
*/

#include "nussl_config.h"

#include <sys/types.h>

#include <string.h>

#include <stdio.h>
#include <ctype.h>		/* isdigit() for nussl_parse_statusline */

#ifdef NUSSL_HAVE_ZLIB
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

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif


#include "nussl_utils.h"
#include "nussl_string.h"	/* for nussl_strdup */
#include "nussl_dates.h"

int nussl_debug_mask = 0;
FILE *nussl_debug_stream = NULL;

void nussl_debug_init(FILE * stream, int mask)
{
	nussl_debug_stream = stream;
	nussl_debug_mask = mask;
#if defined(HAVE_SETVBUF) && defined(_IONBF)
	/* If possible, turn off buffering on the debug log.  this is very
	 * helpful if debugging segfaults. */
	if (stream)
		setvbuf(stream, NULL, _IONBF, 0);
#endif
}

void nussl_debug(int ch, const char *template, ...)
{
	va_list params;
	if ((ch & nussl_debug_mask) == 0)
		return;
	fflush(stdout);
	va_start(params, template);
	vfprintf(nussl_debug_stream, template, params);
	va_end(params);
/*    if ((ch & NUSSL_DBG_FLUSH) == NUSSL_DBG_FLUSH)
	fflush(nussl_debug_stream);*/
}

#define NUSSL_STRINGIFY(x) # x
#define NUSSL_EXPAT_VER(x,y,z) NUSSL_STRINGIFY(x) "." NUSSL_STRINGIFY(y) "." NUSSL_STRINGIFY(z)

static const char version_string[] = "neon " NEON_VERSION ": "
#ifdef NEON_IS_LIBRARY
    "Library build"
#else
    "Bundled build"
#endif
#ifdef NUSSL_HAVE_IPV6
    ", IPv6"
#endif
#ifdef HAVE_EXPAT
    ", Expat"
/* expat >=1.95.2 exported the version */
#ifdef XML_MAJOR_VERSION
    " " NUSSL_EXPAT_VER(XML_MAJOR_VERSION, XML_MINOR_VERSION,
			XML_MICRO_VERSION)
#endif
#else				/* !HAVE_EXPAT */
#ifdef HAVE_LIBXML
    ", libxml " LIBXML_DOTTED_VERSION
#endif				/* HAVE_LIBXML */
#endif				/* !HAVE_EXPAT */
#if defined(NUSSL_HAVE_ZLIB) && defined(ZLIB_VERSION)
    ", zlib " ZLIB_VERSION
#endif				/* NUSSL_HAVE_ZLIB && ... */
#ifdef NUSSL_HAVE_SOCKS
    ", SOCKSv5"
#endif
#ifdef HAVE_OPENSSL
#ifdef OPENSSL_VERSION_TEXT
    ", " OPENSSL_VERSION_TEXT
#else
    "OpenSSL (unknown version)"
#endif				/* OPENSSL_VERSION_TEXT */
#endif				/* HAVE_OPENSSL */
#ifdef HAVE_GNUTLS
    ", GNU TLS " LIBGNUTLS_VERSION
#endif				/* HAVE_GNUTLS */
    ".";

const char *nussl_version_string(void)
{
	return version_string;
}

int nussl_version_match(int major, int minor)
{
	return NUSSL_VERSION_MAJOR != major || NUSSL_VERSION_MINOR < minor
	    || (NUSSL_VERSION_MAJOR == 0 && NUSSL_VERSION_MINOR != minor);
}

int nussl_has_support(int feature)
{
	switch (feature) {
#if defined(NUSSL_HAVE_ZLIB) || defined(NUSSL_HAVE_IPV6) \
    || defined(NUSSL_HAVE_SOCKS) || defined(NUSSL_HAVE_LFS) \
    || defined(NUSSL_HAVE_TS_SSL) || defined(NUSSL_HAVE_I18N)
	case NUSSL_FEATURE_SSL:
#ifdef NUSSL_HAVE_ZLIB
	case NUSSL_FEATURE_ZLIB:
#endif
#ifdef NUSSL_HAVE_IPV6
	case NUSSL_FEATURE_IPV6:
#endif
#ifdef NUSSL_HAVE_SOCKS
	case NUSSL_FEATURE_SOCKS:
#endif
#ifdef NUSSL_HAVE_LFS
	case NUSSL_FEATURE_LFS:
#endif
#ifdef NUSSL_HAVE_TS_SSL
	case NUSSL_FEATURE_TS_SSL:
#endif
#ifdef NUSSL_HAVE_I18N
	case NUSSL_FEATURE_I18N:
#endif
		return 1;
#endif				/* NUSSL_HAVE_* */
	default:
		return 0;
	}
}

int check_key_perms(const char *filename)
{
	struct stat info;

	if (stat(filename, &info) != 0)
		return NUSSL_ERROR;

#ifndef _WIN32
	/* File should not be readable or writable by others */
	if (info.st_mode & S_IROTH || info.st_mode & S_IWOTH)
		return NUSSL_ERROR;
#endif

	return NUSSL_OK;
}
