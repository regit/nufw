/*
 ** Copyright(C) 2003-2006 INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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
 */

#ifndef NUFW_SOURCE_H
#define NUFW_SOURCE_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#ifdef _FEATURES_H
/* Linux */
#   error "nufw_source.h have to be included before <features.h>"
#endif

#ifdef	_SYS_CDEFS_H_
/* FreeBSD */
#   error "nufw_source.h have to be included before <sys/cdefs.h>"
#endif

/**
 * Use POSIX standard, version "IEEE 1003.1-2004",
 * Neded by sigaction (signal.h) and timespec (time.h) for example
 */
#if defined(__linux__)
#  define _POSIX_C_SOURCE 199506L
#endif

/**
 * Use ISO C99 standard, needed by snprintf for example
 */
#define _ISOC99_SOURCE

/**
 * Use 4.3BSD standard,
 * needed to get 'tcphdr' structure and snprintf() function.
 */
#define _BSD_SOURCE

/**
 * Use SVID standard,
 * needed to get 'strdup' from <string.h>.
 */
#define _SVID_SOURCE

/* Disable inline keyword when compiling in strict ANSI conformance */
#if defined(__STRICT_ANSI__) && !defined(__cplusplus)
#  undef inline
#  define inline
#endif

#endif
