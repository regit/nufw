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
   Date manipulation routines
   Copyright (C) 1999-2006, Joe Orton <joe@manyfish.co.uk>
   Copyright (C) 2004 Jiang Lei <tristone@deluxe.ocn.ne.jp>

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

#include <sys/types.h>

#include <time.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef WIN32
#include <windows.h> /* for TIME_ZONE_INFORMATION */
#endif

#include "nussl_alloc.h"
#include "nussl_dates.h"
#include "nussl_string.h"

/* Generic date manipulation routines. */

/* ISO8601: 2001-01-01T12:30:00Z */
#define ISO8601_FORMAT_Z "%04d-%02d-%02dT%02d:%02d:%lfZ"
#define ISO8601_FORMAT_M "%04d-%02d-%02dT%02d:%02d:%lf-%02d:%02d"
#define ISO8601_FORMAT_P "%04d-%02d-%02dT%02d:%02d:%lf+%02d:%02d"

/* RFC1123: Sun, 06 Nov 1994 08:49:37 GMT */
#define RFC1123_FORMAT "%3s, %02d %3s %4d %02d:%02d:%02d GMT"
/* RFC850:  Sunday, 06-Nov-94 08:49:37 GMT */
#define RFC1036_FORMAT "%10s %2d-%3s-%2d %2d:%2d:%2d GMT"
/* asctime: Wed Jun 30 21:49:08 1993 */
#define ASCTIME_FORMAT "%3s %3s %2d %2d:%2d:%2d %4d"

static const char rfc1123_weekdays[7][4] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};
static const char short_months[12][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
#define GMTOFF(t) ((t).tm_gmtoff)
#elif defined(HAVE_STRUCT_TM___TM_GMTOFF)
#define GMTOFF(t) ((t).__tm_gmtoff)
#elif defined(WIN32)
#define GMTOFF(t) (gmt_to_local_win32())
#else
/* FIXME: work out the offset anyway. */
#define GMTOFF(t) (0)
#endif

#ifdef WIN32
time_t gmt_to_local_win32(void)
{
    TIME_ZONE_INFORMATION tzinfo;
    DWORD dwStandardDaylight;
    long bias;

    dwStandardDaylight = GetTimeZoneInformation(&tzinfo);
    bias = tzinfo.Bias;

    if (dwStandardDaylight == TIME_ZONE_ID_STANDARD)
        bias += tzinfo.StandardBias;

    if (dwStandardDaylight == TIME_ZONE_ID_DAYLIGHT)
        bias += tzinfo.DaylightBias;

    return (- bias * 60);
}
#endif

/* Returns the time/date GMT, in RFC1123-type format: eg
 *  Sun, 06 Nov 1994 08:49:37 GMT. */
char *nussl_rfc1123_date(time_t anytime) {
    struct tm *gmt;
    char *ret;
    gmt = gmtime(&anytime);
    if (gmt == NULL)
	return NULL;
    ret = nussl_malloc(29 + 1); /* dates are 29 chars long */
/*  it goes: Sun, 06 Nov 1994 08:49:37 GMT */
    nussl_snprintf(ret, 30, RFC1123_FORMAT,
		rfc1123_weekdays[gmt->tm_wday], gmt->tm_mday,
		short_months[gmt->tm_mon], 1900 + gmt->tm_year,
		gmt->tm_hour, gmt->tm_min, gmt->tm_sec);

    return ret;
}

/* Takes an ISO-8601-formatted date string and returns the time_t.
 * Returns (time_t)-1 if the parse fails. */
time_t nussl_iso8601_parse(const char *date)
{
    struct tm gmt;
    int off_hour, off_min;
    double sec;
    off_t fix;
    int n;

    /*  it goes: ISO8601: 2001-01-01T12:30:00+03:30 */
    if ((n = sscanf(date, ISO8601_FORMAT_P,
		    &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
		    &gmt.tm_hour, &gmt.tm_min, &sec,
		    &off_hour, &off_min)) == 8) {
      gmt.tm_sec = (int)sec;
      fix = - off_hour * 3600 - off_min * 60;
    }
    /*  it goes: ISO8601: 2001-01-01T12:30:00-03:30 */
    else if ((n = sscanf(date, ISO8601_FORMAT_M,
			 &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
			 &gmt.tm_hour, &gmt.tm_min, &sec,
			 &off_hour, &off_min)) == 8) {
      gmt.tm_sec = (int)sec;
      fix = off_hour * 3600 + off_min * 60;
    }
    /*  it goes: ISO8601: 2001-01-01T12:30:00Z */
    else if ((n = sscanf(date, ISO8601_FORMAT_Z,
			 &gmt.tm_year, &gmt.tm_mon, &gmt.tm_mday,
			 &gmt.tm_hour, &gmt.tm_min, &sec)) == 6) {
      gmt.tm_sec = (int)sec;
      fix = 0;
    }
    else {
      return (time_t)-1;
    }

    gmt.tm_year -= 1900;
    gmt.tm_isdst = -1;
    gmt.tm_mon--;

    return mktime(&gmt) + fix + GMTOFF(gmt);
}
