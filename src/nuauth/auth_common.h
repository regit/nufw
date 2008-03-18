/*
 ** Copyright(C) 2005-2007 Eric Leblond <regit@inl.fr>
 **                  INL http://www.inl.fr/
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

#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#define SHL32(x, n) (((int)(n)<=0)?(x):(((n) < 32)?((x) << (n)):0))
#define SHR32(x, n) (((int)(n)<=0)?(x):(((n) < 32)?((x) >> (n)):0))

typedef enum {
	PACKET_ALONE = 0,	/*!< The packet is not linked with the main hash ::conn_list */
	PACKET_IN_HASH		/*!< Packet is stored inside ::conn_list */
} packet_place_t;

gboolean tracking_equal(const tracking_t *trck1, const tracking_t *trck2);
void *search_and_fill(GMutex * mutex);

int sck_auth_reply;

char *get_rid_of_domain(const char *user);
char *get_rid_of_prefix_domain(const char *user);

void free_buffer_read(struct tls_buffer_read *datas);

/*
 * Keep connection in a hash
 */

#ifdef PERF_DISPLAY_ENABLE
int timeval_substract(struct timeval *result, struct timeval *x,
		      struct timeval *y);
#endif

nu_error_t check_protocol_version(enum proto_type_t type, int version);

int str_to_int(const char *text, int *value);
int str_to_uint32(const char *text, uint32_t *value);
int str_to_long(const char *text, long *value);
int str_to_ulong(const char *text, unsigned long *value);
char *int_to_str(int value);

void thread_pool_push(GThreadPool *pool, gpointer data, GError **error);

int parse_addr_port(const char *text, const char* default_port, char **addr, char **port);

#endif
