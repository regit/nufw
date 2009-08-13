/*
 ** Copyright(C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
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

int secure_snprintf(char *buffer, size_t buffer_size,
			 char *format, ...)
#ifdef __GNUC__
	__attribute__((__format__(printf,3,4)))
#endif
;

char *str_extract_until(const char *str, int c);

int str_to_long(const char *text, long *value);
int str_to_ulong(const char *text, unsigned long *value);
int str_to_int(const char *text, int *value);
int str_to_uint32(const char *text, uint32_t * value);
char *str_itoa(int i);
void bin2hex(int len, unsigned char *binnum, char *hexnum);
