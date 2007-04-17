/*
 ** Copyright(C) 2007 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
 **
 ** $Id: command.h 2738 2007-02-17 13:59:56Z regit $
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

#ifndef COMMAND_NEW_H
#define COMMAND_NEW_H

#include "auth_srv.h"

typedef struct {
	char *data;
	size_t size;
	size_t alloc_size;
} encoder_t;

encoder_t* encoder_new();
void encoder_destroy(encoder_t* encoder);
void encoder_slist_destroy(GSList *item_list);

void encoder_add_int32(encoder_t* encoder, uint32_t value);
void encoder_add_ipv6(encoder_t* encoder, const struct in6_addr *ipv6);
void encoder_add_string(encoder_t* encoder, const char *string);
void encoder_add_tuple(encoder_t* encoder, size_t count, encoder_t *items);
void encoder_add_tuple_from_slist(encoder_t* encoder, GSList *item_list);
void encoder_add_uptime(encoder_t* encoder, time_t start, time_t diff);

encoder_t* encode_answer(uint8_t ok, encoder_t *data);
encoder_t* encode_user(user_session_t *session);
encoder_t* encode_nufw(nufw_session_t *session);

#endif /* COMMAND_NEW_H */

