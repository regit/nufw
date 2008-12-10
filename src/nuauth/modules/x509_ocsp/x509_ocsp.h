/*
** Copyright(C) 2008 INL
**          written by Pierre Chifflier <chifflier@inl.fr>
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

#ifndef __X509_OCSP_H__
#define __X509_OCSP_H__

struct x509_ocsp_params {
	gchar *ca;

	gchar *ocsp_server;
	unsigned int ocsp_port;
	gchar *ocsp_path;
};

int check_ocsp(nussl_session *session, gpointer params_p);

#endif /* __X509_OCSP_H__ */

