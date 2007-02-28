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

#include "command_enc.h"
#include "command_codec.h"

/**
 * Create a new encoder
 */
encoder_t* encoder_new()
{
	return g_new0(encoder_t, 1);
}

/**
 * Allocate more size bytes to the encoder
 */
void encoder_grow(encoder_t* encoder, size_t size)
{
	size_t newsize = encoder->size + size;
	if (encoder->alloc_size < newsize)
	{
		newsize = newsize * 3 / 2;
		if (newsize < 16) newsize = 16;
		encoder->data = g_realloc(encoder->data, newsize);
		encoder->alloc_size = newsize;
	}
}

/**
 * Write a bytecode in the encoder
 */
void encoder_write_bytecode(encoder_t* encoder, char bytecode)
{
	encoder->data[encoder->size] = bytecode;
	encoder->size += 1;
}

/**
 * Write a 32-bit integer in the encoder
 */
void encoder_write_int32(encoder_t* encoder, int32_t value)
{
	int32_t *ptr = (int32_t*)(encoder->data + encoder->size);
	*ptr = htonl(value);
	encoder->size += 4;
}

/**
 * Write bytes in the encoder
 */
void encoder_write_bytes(encoder_t* encoder, int size, const void* data)
{
	memcpy(encoder->data + encoder->size, data, size);
	encoder->size += size;
}

/**
 * Add a bytecode to the encoder
 */
void encoder_add_bytecode(encoder_t* encoder, char bytecode)
{
	encoder_grow(encoder, 1);
	encoder_write_bytecode(encoder, bytecode);
}

/**
 * Add a 32-bit integer to the encoder: ('i', value)
 */
void encoder_add_int32(encoder_t* encoder, uint32_t value)
{
	encoder_grow(encoder, 5);
	encoder_write_bytecode(encoder, BYTECODE_INT32);
	encoder_write_int32(encoder, value);
}

/**
 * Add an IPv6 address: ('p', data)
 */
void encoder_add_ipv6(encoder_t* encoder, const struct in6_addr *ipv6)
{
	const unsigned int len = 16;
	encoder_grow(encoder, 1 + len);
	encoder_write_bytecode(encoder, BYTECODE_IPV6);
	encoder_write_bytes(encoder, len, ipv6);
}

/**
 * Add a string to the encoder: ('s', length, data)
 */
void encoder_add_string(encoder_t* encoder, const char *string)
{
	size_t len = strlen(string);
	encoder_grow(encoder, 5 + len);
	encoder_write_bytecode(encoder, BYTECODE_STRING);
	encoder_write_int32(encoder, len);
	encoder_write_bytes(encoder, len, string);
}

/**
 * Add a tuple to the encoder: ('(', count, item0, item1, ...)
 */
void encoder_add_tuple(encoder_t* encoder, size_t count, encoder_t *items)
{
	size_t len = 0;
	size_t index;
	for (index=0; index<count; index++)
	{
		len += items[index].size;
	}
	encoder_grow(encoder, 5 + len);
	encoder_write_bytecode(encoder, BYTECODE_TUPLE);
	encoder_write_int32(encoder, count);
	for (index=0; index<count; index++)
	{
		encoder_t *item = &items[index];
		encoder_write_bytes(encoder, item->size, item->data);
	}
}

/**
 * Add a tuple from a single linked list of encoders:
 * ('(', count, item0, item1, ...)
 *
 * Then you can use encoder_slist_destroy() to delete your list.
 */
void encoder_add_tuple_from_slist(encoder_t* encoder, GSList *item_list)
{
	size_t count = 0;
	size_t size = 0;
	GSList* iter;

	/* count number of item and total message size */
	for (iter=item_list; iter; iter=iter->next)
	{
		encoder_t *item = iter->data;
		count += 1;
		size += item->size;
	}

	/* write data */
	encoder_grow(encoder, 5 + size);
	encoder_write_bytecode(encoder, BYTECODE_TUPLE);
	encoder_write_int32(encoder, count);
	for (iter=item_list; iter; iter=iter->next)
	{
		encoder_t *item = iter->data;
		encoder_write_bytes(encoder, item->size, item->data);
	}
}

/**
 * Add an answer: ('a', datalen, ok, data)
 */
encoder_t* encode_answer(uint8_t ok, encoder_t *data)
{
	encoder_t* encoder = encoder_new();
	encoder_add_bytecode(encoder, BYTECODE_ANSWER);
	encoder_add_int32(encoder, data->size);
	encoder_add_int32(encoder, ok);
	encoder_grow(encoder, data->size);
	encoder_write_bytes(encoder, data->size, data->data);
	return encoder;
}

/**
 * Add uptime message: ('U', start, diff)
 */
encoder_t* encode_uptime(time_t start, time_t diff)
{
	encoder_t* encoder = encoder_new();
	encoder_add_bytecode(encoder, BYTECODE_UPTIME);
	encoder_add_int32(encoder, start);
	encoder_add_int32(encoder, diff);
	return encoder;
}

/**
 * Add user message: ('u', ...)
 */
encoder_t* encode_user(user_session_t* session)
{
	encoder_t *encoder;
	GSList *group;
	GSList *groups = NULL;

	/* create group list */
	for (group=session->groups; group; group=g_slist_next(group)) {
		encoder_t *group_data;
		unsigned int gid = GPOINTER_TO_UINT(group->data);

		group_data = encoder_new();
		encoder_add_int32(group_data, gid);
		groups = g_slist_prepend(groups, group_data);
	}

	/* encode user entry */
	encoder = encoder_new();
	encoder_add_bytecode(encoder, BYTECODE_USER);
	encoder_add_int32(encoder, session->client_version);
	encoder_add_int32(encoder, session->socket);
	encoder_add_string(encoder, session->user_name);
	encoder_add_ipv6(encoder, &session->addr);
	encoder_add_int32(encoder, session->sport);
	encoder_add_int32(encoder, session->user_id);
	encoder_add_tuple_from_slist(encoder, groups);
	encoder_add_int32(encoder, session->connect_timestamp);
	encoder_add_int32(encoder, session->expire);

	/* destroy group list */
	encoder_slist_destroy(groups);
	return encoder;
}

/**
 * Encode a text
 */
encoder_t* encode_text(const char* text)
{
	encoder_t* encoder = encoder_new();
	encoder_add_string(encoder, text);
	return encoder;
}

/**
 * Destroy an encoder (free memory)
 */
void encoder_destroy(encoder_t *encoder)
{
	g_free(encoder->data);
	g_free(encoder);
}

/**
 * Delete a single linked list of encoders.
 */
void encoder_slist_destroy(GSList *item_list)
{
	g_slist_foreach(item_list, (GFunc)encoder_destroy, NULL);
	g_slist_free(item_list);
}

