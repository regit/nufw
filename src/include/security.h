/*
 ** Copyright(C) 2006 INL
 ** Written by Victor Stinner <haypo@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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


#ifndef _NUFW_SECURITY_H
#define _NUFW_SECURITY_H

/** \def SECURE_STRNCPY(dst,src,size)
 * Copy string src to dst. Copy at maximum size-1 characters and make
 * sure that the string finish with a '\\0'.
 *
 * Workaround strncpy security problem: if size is smaller than strlen(src),
 * dst doesn't contains '\\0'. This macro copy on maximum size-1 characters,
 * and always write a '\\0' on last position (dst[size-1]).
 */
#define SECURE_STRNCPY(dst, src, size) \
    do { strncpy(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while (0)

/** \def SECURE_STRNCAT(dst,src,size)
 * Copy string src to dst. Copy at maximum size-1 characters and make
 * sure that the string finish with a '\\0'.
 *
 * Workaround strncat security problem: if size is smaller than strlen(src),
 * dst doesn't contains '\\0'. This macro copy on maximum size-1 characters,
 * and always write a '\\0' on last position (dst[size-1]).
 */
#define SECURE_STRNCAT(dst, src, size) \
    do { strncat(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while (0)

#endif				/* of ifndef _NUFW_SECURITY_H */
