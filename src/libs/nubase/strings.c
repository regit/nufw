/*
 ** Copyright (C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>         /* isspace() */

#include <nubase.h>

/**
 * \addtogroup Nubase
 *
 * @{
 */

/**
 *
 * \file nubase/strings.c
 * \brief String utility functions
 */

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
char *str_extract_until(const char *str, int c)
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
	newstr = malloc(newstr_size + 2);
	if ( ! newstr ) return NULL;

	for (i=0;i<newstr_size;i++) {
		newstr[i] = *str++;
	}

	newstr[i] = c;
	newstr[i+1] = '\0';

	return newstr;

}

/**
 * Convert a string to a signed long integer number.
 * Skip spaces before first digit.
 * Return 0 on error, 1 otherwise.
 */
int str_to_long(const char *text, long *value)
{
	char *err = NULL;
	long longvalue;

	/* skip spaces */
	while (isspace(*text))
		text++;

	/* call strtol */
	longvalue = strtol(text, &err, 10);
	if (err == NULL || *err != 0)
		return 0;
	*value = longvalue;
	return 1;
}

/**
 * Convert a string to an unsigned long integer number.
 * Skip spaces before first digit.
 * Return 0 on error, 1 otherwise.
 */
int str_to_ulong(const char *text, unsigned long *value)
{
	char *err = NULL;
	unsigned long ulongvalue;

	/* skip spaces */
	while (isspace(*text))
		text++;

	/* call strtol */
	ulongvalue = strtoul(text, &err, 10);
	if (err == NULL || *err != 0)
		return 0;
	*value = ulongvalue;
	return 1;
}

/**
 * Convert a string to integer number (value in INT_MIN..INT_MAX).
 * Skip spaces before number value if any.
 * Return 0 on error, 1 otherwise.
 */
int str_to_int(const char *text, int *value)
{
	long longvalue;
	if (!str_to_long(text, &longvalue))
		return 0;
	if (longvalue < INT_MIN || INT_MAX < longvalue)
		return 0;
	*value = (int)longvalue;
	return 1;
}

/**
 * Convert a string to a 32-bit unsigned integer (value in 0..4294967295).
 * Skip spaces before number value if any.
 * Returns 0 on error, 1 otherwise.
 */
int str_to_uint32(const char *text, uint32_t * value)
{
	unsigned long ulongvalue;
	if (!str_to_ulong(text, &ulongvalue))
		return 0;
	if (4294967295UL < ulongvalue)
		return 0;
	*value = (uint32_t)ulongvalue;
	return 1;
}

char *str_itoa(int i)
{

	char *str;
	int strsize;
	int ret;

	strsize = snprintf(NULL, 0, "%d", i);
	if ( strsize <= 0 ) return strdup("");
	str = malloc(strsize + 1);
	if ( ! str ) return strdup("");
	ret = snprintf(str, strsize + 1, "%d", i);
	if ( ret <= 0 ) return strdup("");

	str[ret] = '\0';

	return str;
}

/** @} */
