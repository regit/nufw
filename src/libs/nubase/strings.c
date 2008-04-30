/*
 ** Copyright (C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
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
#include <stdio.h>
#include <stdarg.h>

#include <nubase.h>

/**
 * Function snprintf() which check buffer overflow, and always write a '\\0'
 * to the end of the buffer.
 *
 * \param buffer Buffer where characters are written
 * \param buffer_size Buffer size (in bytes), usually equals to sizeof(buffer)
 * \param format Format string (see printf() documentation)
 * \return Returns FALSE if a buffer overflow occurs, TRUE is everything goes fine.
 */
int secure_snprintf(char *buffer, size_t buffer_size,
			 char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
#ifdef DEBUG_ENABLE
	memset(buffer, 0, buffer_size);
#else
	buffer[0] = 0;
#endif
	ret = vsnprintf(buffer, buffer_size, format, args);
	va_end(args);
	buffer[buffer_size - 1] = '\0';
	if (0 <= ret && ret <= ((int) buffer_size - 1))
		return TRUE;
	else
		return FALSE;
}

