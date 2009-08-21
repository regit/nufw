/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/*
   Date manipulation routines
   Copyright (C) 1999-2002, 2005, Joe Orton <joe@manyfish.co.uk>

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

#ifndef NUSSL_DATES_H
#define NUSSL_DATES_H

#include <sys/types.h>

#include "nussl_defs.h"

NUSSL_BEGIN_DECLS
/* Date manipulation routines as per RFC1123 and RFC1036 */
/* Return current date/time in RFC1123 format */
char *nussl_rfc1123_date(time_t anytime);

/* Returns time from date/time using the subset of the ISO8601 format
 * referenced in RFC2518 (e.g as used in the creationdate property in
 * the DAV: namespace). */
time_t nussl_iso8601_parse(const char *date);

NUSSL_END_DECLS
#endif				/* NUSSL_DATES_H */
