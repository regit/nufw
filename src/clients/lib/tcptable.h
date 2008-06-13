/*
 ** Copyright 2005 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr
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

#ifndef TCPTABLE_H
#define TCPTABLE_H

int tcptable_init(conntable_t ** ct);
int tcptable_read(nuauth_session_t * session, conntable_t * ct);
void tcptable_add(conntable_t * ct, conn_t * c);
void tcptable_free(conntable_t * ct);
int tcptable_hash(conn_t * c);
conn_t *tcptable_find(conntable_t * ct, conn_t * c);

#endif
