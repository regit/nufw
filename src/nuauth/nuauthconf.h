/*
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

#ifndef NUAUTHCONF_H
#define NUAUTHCONF_H

int build_nuauthconf(struct nuauth_params * nuauthconf,
                char* nuauth_client_listen_addr,
                char* nuauth_nufw_listen_addr,
                char* gwsrv_addr,
                char* nuauth_multi_users,
                char* nuauth_multi_servers);

struct nuauth_params*   init_nuauthconf();

void nuauth_reload( int signal );

#endif
