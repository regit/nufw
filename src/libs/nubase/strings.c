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
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

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

/**
 * Function which extracts a string until char 'c'
 * is found
 *
 * \param str input string
 * \param c character to match the string until
 * \return Returns NULL if error, or the new allocated string
 */
char *str_extract_until(char *str, int c)
{
	unsigned int i;

	char *newstr;
	char *last_str;

	size_t last_size;
	size_t str_size;
	size_t newstr_size;

	last_str = strrchr(str, c);
	if ( ! last_str ) return NULL;
	last_size = strlen(last_str);
	str_size = strlen(str);
	newstr_size = str_size - last_size;
	newstr = malloc(newstr_size);
	if ( ! newstr ) return NULL;

	for (i=0;i<newstr_size;i++) {
		newstr[i] = *str++;
	}

	newstr[i] = '\0';

	return newstr;

}

/**
 * Util function returning a string
 * from an integer.
 *
 * Use of sprintf() because int is
 * a controlled value. However this
 * function must be used with care.
 *
 * \param i integer to convert
 * \return Returns the string equivalent to i
 */
char *str_itoa(int i)
{
	char *str;
	// Check the number we'll fit in the buffer
	if(i >= 1000)
		return strdup("");
	str = malloc(sizeof(int));
	if ( ! str ) return strdup("");
	sprintf(str, "%d", i);
	return str;
}

