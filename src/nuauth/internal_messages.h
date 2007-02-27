/*
** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
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

#ifndef INTERNAL_MESSAGES_H
#define INTERNAL_MESSAGES_H

/*
 * message structure for async communication
 * between cache thread and others
 *
 * See push_worker().
 */
typedef enum {
	FREE_MESSAGE = 0,	/*!< Call delete_client_by_socket() / used in cache_manager() */
	WARN_MESSAGE,		/*!< Warn clients: see warn_clients() */
	INSERT_MESSAGE,		/*!< Call add_client() / used in cache_manager() */
	UPDATE_MESSAGE,		/*!< Used in cache_manager() */
	GET_MESSAGE,		/*!< Used in cache_manager() */
	REFRESH_MESSAGE,		/*!< Used in cache_manager() */
	RESET_MESSAGE		/*!< Used in cache_manager() to make all entry perish */
} internal_message_type_t;

struct internal_message {
	internal_message_type_t type;
	gpointer datas;
};


#endif
