/*
** Copyright(C) 2006-2010 EdenWall Technologies
**          written by Eric Leblond <regit@inl.fr>
**                     Pierre Chifflier <chifflier@edenwall.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 3 of the License.
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

#ifndef __NUAUTH_X509_STD__
#define __NUAUTH_X509_STD__

struct x509_std_params {
	gchar *trusted_issuer_dn;
	gchar *uid_method;
	gchar **uid_method_list;
};

#endif /* __NUAUTH_X509_STD__ */

