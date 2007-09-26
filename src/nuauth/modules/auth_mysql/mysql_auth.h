/*
 ** Copyright(C) 2003-2007 Wi-Next
 ** Written by Francesco Varano	- <francesco.varano@winext.eu>
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

#ifndef IPAUTH_H
#define IPAUTH_H

#include <auth_srv.h>
#include <string.h>
#include <errno.h>
#include "mysql.h"

#define AUTH_MYSQL_FALLBACK_TO_GUEST 1
#define AUTH_MYSQL_GUEST_USERNAME "guest"
#define AUTH_MYSQL_GUEST_USERID 0
#define AUTH_MYSQL_GUEST_GROUPID 99

#define IPAUTH_REV "0.0.1"

struct ipauth_user {
	char *username;
	/* char *passwd; */
	u_int32_t uid;
	GSList *groups;
};

struct ipauth_params {
	struct ipauth_mysql_params *mysql;
	unsigned char fallback_to_guest;
	char *guest_username;
	unsigned guest_uid;
	unsigned guest_gid;
	GHashTable *users; 
};

#endif /* IPAUTH_H */

