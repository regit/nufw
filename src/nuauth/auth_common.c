/*
 ** Copyright(C) 2003-2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@gryzor.com>
 **     INL : http://www.inl.fr/
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

#include "auth_srv.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <ctype.h>         /* isspace() */

/**
 * \ingroup Nuauth
 * \defgroup NuauthCore Nuauth Core
 * \brief This is the main part of nuauth, real core is search_and_fill().
 * \author Éric Leblond
 *
 * The main functions are :
 *  - search_and_fill() : used to aggregate dates coming from nufw and clients
 *  - take_decision() : decide on packet based on policy coming from module
 *
 * @{
 *
 */

/** \file auth_common.c
 *  \brief Core functions of NuAuth, contain search_and_fill() .
 */

#ifdef PERF_DISPLAY_ENABLE
/* Subtract the `struct timeval' values X and Y,
 *         storing the result in RESULT.
 *                 Return 1 if the difference is negative, otherwise 0.  */

int timeval_substract(struct timeval *result, struct timeval *x,
		      struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 *           tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}
#endif

/**
 * Check if a IPv6 address is a IPv4 or not.
 *
 * \return 1 for IPv4 and 0 for IPv6
 */
int is_ipv4(struct in6_addr *addr)
{
	if (addr->s6_addr32[2] != 0xffff0000)
		return 0;
	if (addr->s6_addr32[0] != 0 || addr->s6_addr32[1] != 0)
		return 0;
	return 1;
}

/**
 * Suppress domain from "user\@domain" string (returns "user").
 *
 * \return Username which need to be freeded
 */
char *get_rid_of_domain(const char *user_domain)
{
	char *username = NULL;
	char **user_realm;
	user_realm = g_strsplit(user_domain, "@", 2);
	if (user_realm[0] != NULL) {
		username = g_strdup(user_realm[0]);
	} else {
		username = g_strdup(user_domain);
	}
	g_strfreev(user_realm);
	return username;
}

/**
 * Suppress domain from "DOMAIN\user" string (returns "user").
 *
 * \return Username which need to be freeded
 */
char *get_rid_of_prefix_domain(const char *user_domain)
{
	char *username = NULL;
	char **user_realm;
	user_realm = g_strsplit(user_domain, "\\", 2);
	if (user_realm[0] && user_realm[1]) {
		username = g_strdup(user_realm[1]);
	} else {
		username = g_strdup(user_domain);
	}
	g_strfreev(user_realm);
	return username;
}

/**
 * Free a ::tls_buffer_read buffer and all of its memory.
 */
void free_buffer_read(struct tls_buffer_read *datas)
{
	g_free(datas->os_sysname);
	g_free(datas->os_release);
	g_free(datas->os_version);
	g_free(datas->buffer);
	g_free(datas->user_name);
	if (datas->groups != NULL) {
		g_slist_free(datas->groups);
	}
	g_free(datas);
}

/**
 * Function snprintf() which check buffer overflow, and always write a '\\0'
 * to the end of the buffer.
 *
 * \param buffer Buffer where characters are written
 * \param buffer_size Buffer size (in bytes), usually equals to sizeof(buffer)
 * \param format Format string (see printf() documentation)
 * \return Returns FALSE if a buffer overflow occurs, TRUE is everything goes fine.
 */
gboolean secure_snprintf(char *buffer, unsigned int buffer_size,
			 char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = g_vsnprintf(buffer, buffer_size, format, args);
	va_end(args);
	buffer[buffer_size - 1] = '\0';
	if (0 <= ret && ret <= ((int) buffer_size - 1))
		return TRUE;
	else
		return FALSE;
}

/**
 * Check Protocol version agains supported one
 *
 * \param version A integer coding protocol version to test
 * \return a ::nu_error_t
 */

nu_error_t check_protocol_version(int version)
{
	if ((version != PROTO_VERSION) && (version != PROTO_VERSION_V20)) {
		return NU_EXIT_ERROR;
	} else {
		return NU_EXIT_OK;
	}
}

/**
 * Convert an integer to a string.
 * Return 0 on error, 1 otherwise.
 */
char* int_to_str(int value)
{
	return g_strdup_printf("%i", value);
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

/**
 * Wrapper to g_thread_pool_push(): block on server reload.
 */
void thread_pool_push(GThreadPool *pool, gpointer data, GError **error)
{
	block_on_conf_reload();
	g_thread_pool_push(pool, data, error);
}

/** @} */
