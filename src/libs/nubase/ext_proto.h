/*
 ** Copyright(C) 2009 INL
 ** Written by Eric Leblond <eleblond@inl.fr>
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
 **
 */

typedef enum _ext_proto_state_t {
	EXT_PROTO_OUTSIDE,
	EXT_PROTO_START,
	EXT_PROTO_CMD,
	EXT_PROTO_END,
} ext_proto_state_t;

struct proto_ext_cmd_t {
	char *cmdname;
	int nargs;
	int (*callback)(char **buf, int bufsize, void *data);
};

struct proto_ext_t {
	struct llist_head list;
	char * name;
	int ncmd;
	struct proto_ext_cmd_t cmd[];
};

int process_ext_message(char *buf, int bufsize, struct llist_head *ext_proto, void *data);

