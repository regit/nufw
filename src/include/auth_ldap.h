/* $Id: auth_ldap.h,v 1.3 2003/09/14 21:29:38 gryzor Exp $ */

/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 2 of the License.
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
#define LDAP_BASE "dc=regit,dc=org"

