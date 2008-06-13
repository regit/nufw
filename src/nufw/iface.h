/*
 ** Copyright (C) 2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
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

#ifndef IFACE_H
#define IFACE_H

#ifdef HAVE_NFQ_INDEV_NAME
int get_interface_information(struct nlif_handle *inst,
			      struct queued_pckt *q_pckt,
			      struct nfq_data *nfad);

struct nlif_handle *iface_table_open();
int iface_treat_message(struct nlif_handle *inst);

void iface_table_close(struct nlif_handle *inst);
#endif

#endif
