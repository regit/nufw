/* $Id: auth_ldap.h,v 1.1 2003/08/25 19:19:14 regit Exp $ */

/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
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

#include <sys/time.h>
#include <ldap.h>


#define LDAP_SERVER "127.0.0.1"
/*#define LDAP_USER NULL
#define LDAP_CRED NULL */
#define LDAP_USER "cn=admin,dc=regit,dc=org"
#define LDAP_CRED "tadadaa" 
#define LDAP_REQUEST_TIMEOUT 10

//LDAP * ld;
