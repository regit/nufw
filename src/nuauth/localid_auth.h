/*
** Copyright(C) 2005,2009 INL
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

#ifndef LOCALID_AUTH_H
#define LOCALID_AUTH_H

/* from localid_auth */
char localid_authenticated_protocol(connection_t *conn);
void *localid_auth(GMutex * mutex);

#endif
