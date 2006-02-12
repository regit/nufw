/*
** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
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
 */


#define WARN_MESSAGE 0x1
#define FREE_MESSAGE 0x0
#define INSERT_MESSAGE 0x2
#define UPDATE_MESSAGE 0x3
#define GET_MESSAGE 0x4
#define REFRESH_MESSAGE 0x5

struct internal_message {
	guint type;
	gpointer datas;
};


#endif
