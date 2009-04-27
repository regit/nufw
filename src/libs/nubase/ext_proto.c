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
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "nubase.h"
#include <stdio.h> /* sscanf() */
#include <string.h> /* sscanf() */
#include <sasl/sasl.h>
#include <security.h>

int process_ext_message(char *buf, int bufsize, struct llist_head * ext_proto_l, void *data)
{
	char pbuf[1024];
	char *lbuf = buf;
	int state = EXT_PROTO_OUTSIDE;
	int i, ret;
	struct proto_ext_t *p_ext_proto = NULL;
	struct proto_ext_t *pos;

	do {
		sscanf(lbuf,"%s", pbuf);
		lbuf += strlen(pbuf) + 1;
		switch (state) {
			case EXT_PROTO_OUTSIDE:
				/* should find "BEGIN" */
				if (! strcmp(pbuf, "BEGIN")) {
					state = EXT_PROTO_START;
					p_ext_proto = NULL;
				}
				break;
			case EXT_PROTO_START:
				/* iter on entries */
				llist_for_each_entry(pos, ext_proto_l, list) {
					if (! strcmp(pbuf, pos->name)) {
						p_ext_proto = pos;
						state = EXT_PROTO_CMD;
						break;
					}
				}
				if (p_ext_proto == NULL) {
					/* unknown protocol */
					return SASL_FAIL;
				}
				break;
			case EXT_PROTO_CMD:
				if (! strcmp(pbuf, "END")) {
					state = EXT_PROTO_OUTSIDE;
				}
				for (i = 0; i < p_ext_proto->ncmd; i++) {
					if (! strcmp(pbuf, p_ext_proto->cmd[i].cmdname)) {
						/* call callback */
						ret = p_ext_proto->cmd[i].callback(&lbuf,
										 bufsize - (lbuf - buf),
										 data);
						if (ret != SASL_OK) {
							return ret;
						}
					}
				}
				break;
		}
	} while (lbuf < buf + bufsize);

	return SASL_OK;
}


