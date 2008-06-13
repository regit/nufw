/*
 ** Copyright(C) 2006, INL
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

#ifndef PCKT_AUTHSRV_V3_H
#define  PCKT_AUTHSRV_V3_H
nu_error_t authpckt_conntrack_v3(unsigned char *dgram, unsigned int dgram_size);

nu_error_t authpckt_new_connection_v3(unsigned char *dgram,
				      unsigned int dgram_size,
				      connection_t ** conn);

#endif
