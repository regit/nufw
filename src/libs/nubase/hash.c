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

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "linuxlist.h"

struct hash_t {
	struct llist_head list;
	void *key;
	void *value;
} hash_t;

LLIST_HEAD(hash_list);

char *nubase_hash_get(char *key)
{
	struct hash_t *hash;

	llist_for_each_entry(hash, &hash_list, list) {
		if (!strncmp(key, hash->key, strlen(hash->key))) {
			return hash->value;
		}
	}

	return NULL;
}

struct hash_t *nubase_hash_append(char *key, char *value)
{
	struct hash_t *hash;

	if (nubase_hash_get(key)) return NULL;

	hash = malloc(sizeof(*hash));
	if ( ! hash ) {
		errno = ENOMEM;
		return NULL;
	}

	hash->key = key;
	hash->value = value;

	llist_add_tail(&hash->list, &hash_list);

	return hash;
}

#ifdef _UNIT_TEST_
#include <stdio.h>
int main(void)
{
	struct hash_t *hash;
	int i = 0;

	nubase_hash_append("foo", "bar");
	nubase_hash_append("foo", "bar");
	nubase_hash_append("nu", "pik");
	nubase_hash_append("tout", "foulcan");
	nubase_hash_append("jean", "nemard");

	printf("\n........................\nllist_for_each_entry\n........................\n");

	llist_for_each_entry(hash, &hash_list, list) {
		printf("key=%s, value=%s\n", hash->key, hash->value);
	}

	printf("\n........................\nnubase_hash_get\n........................\n");
	printf("The value for 'nu' is '%s'\n", nubase_hash_get("nu"));

}
#endif

