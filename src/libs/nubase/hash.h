/*
 ** Copyright(C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
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

#ifndef _HASH_H_
#define _HASH_H_

struct hash_t {
	struct llist_head list;
	void *key;
	void *value;
} hash_t;

char *nubase_hash_get(char *key);
struct hash_t *nubase_hash_append(char *key, char *value);

#endif /* _HASH_H_ */

