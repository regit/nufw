
/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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

#include <auth_srv.h>

/*
 * check packet contained in element against
 * an external base (ldap,radius,...)
 */

/*
 * external_acl_groups :
 * Fill in acl_groups of a connection by calling external module
 * Argument : a connection
 * Return : 1 if OK, 0 otherwise
 */

int external_acl_groups (connection * element){
  GSList * acl_groups=NULL;

  /* query external authority */

  acl_groups = (*module_acl_check) (element);

  if (acl_groups != NULL){
  	element->acl_groups=acl_groups;
	return 1;
  }
  return 0;
}

