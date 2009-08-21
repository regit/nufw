/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

   In addition, as a special exception, INL
   gives permission to link the code of its release of NuSSL with the
   OpenSSL project's "OpenSSL" library (or with modified versions of it
   that use the same license as the "OpenSSL" library), and distribute
   the linked executables.  You must obey the GNU General Public License
   in all respects for all of the code used other than "OpenSSL".  If you
   modify this file, you may extend this exception to your version of the
   file, but you are not obligated to do so.  If you do not wish to do
   so, delete this exception statement from your version.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "nussl_ssl_common.h"
#include "nussl_private.h"
#include "nussl_privssl.h"
#include "nussl_ssl.h"
#include "nussl_internal.h"
#include "nussl_alloc.h"

char *nussl_get_cert_info(nussl_session * sess)
{
	char valid_from[NUSSL_SSL_VDATELEN];
	char valid_until[NUSSL_SSL_VDATELEN];
	char *ret, *dn, *issuer_dn, *dn_str, *issuer_str, *from_str,
	    *until_str;

	if (!sess->my_cert)
		return NULL;

	dn = nussl_ssl_readable_dname(&sess->my_cert->cert.subj_dn);
	issuer_dn =
	    nussl_ssl_readable_dname(&sess->my_cert->cert.issuer_dn);
	nussl_ssl_cert_validity(&sess->my_cert->cert, valid_from,
				valid_until);

	dn_str = _("DN: ");
	issuer_str = _("Issuer DN: ");
	from_str = _("Valid from: ");
	until_str = _("Valid until: ");

	ret = (char *) malloc(strlen(dn) + strlen(issuer_dn) + strlen(valid_from) + strlen(valid_until) + strlen(dn_str) + strlen(issuer_str) + strlen(from_str) + strlen(until_str) + 5);	/* 5 = 4 '\n' and 1 '\0' */

	if (!ret) {
		nussl_free(dn);
		nussl_free(issuer_dn);
		return NULL;
	}

	strcpy(ret, dn_str);
	strcat(ret, dn);
	strcat(ret, "\n");
	strcat(ret, issuer_str);
	strcat(ret, issuer_dn);
	strcat(ret, "\n");
	strcat(ret, from_str);
	strcat(ret, valid_from);
	strcat(ret, "\n");
	strcat(ret, until_str);
	strcat(ret, valid_until);
	strcat(ret, "\n");

	nussl_free(dn);
	nussl_free(issuer_dn);

	return ret;
}

char *nussl_get_server_cert_info(nussl_session * sess)
{
	char valid_from[NUSSL_SSL_VDATELEN];
	char valid_until[NUSSL_SSL_VDATELEN];
	char *ret, *dn, *issuer_dn, *dn_str, *issuer_str, *from_str,
	    *until_str;

	if (!sess->peer_cert)
		return NULL;

	dn = nussl_ssl_readable_dname(&sess->peer_cert->subj_dn);
	issuer_dn = nussl_ssl_readable_dname(&sess->peer_cert->issuer_dn);
	nussl_ssl_cert_validity(sess->peer_cert, valid_from, valid_until);

	dn_str = _("DN: ");
	issuer_str = _("Issuer DN: ");
	from_str = _("Valid from: ");
	until_str = _("Valid until: ");

	ret = (char *) nussl_malloc(strlen(dn) + strlen(issuer_dn) + strlen(valid_from) + strlen(valid_until) + strlen(dn_str) + strlen(issuer_str) + strlen(from_str) + strlen(until_str) + 5);	/* 5 = 4 '\n' and 1 '\0' */

	if (!ret) {
		nussl_free(dn);
		nussl_free(issuer_dn);
		return NULL;
	}

	strcpy(ret, dn_str);
	strcat(ret, dn);
	strcat(ret, "\n");
	strcat(ret, issuer_str);
	strcat(ret, issuer_dn);
	strcat(ret, "\n");
	strcat(ret, from_str);
	strcat(ret, valid_from);
	strcat(ret, "\n");
	strcat(ret, until_str);
	strcat(ret, valid_until);
	strcat(ret, "\n");

	nussl_free(dn);
	nussl_free(issuer_dn);

	return ret;
}

char *nussl_get_server_cert_dn(nussl_session * sess)
{
	char *tmp, *dn;
	if (!sess->peer_cert) {
		nussl_set_error(sess,
				_("The peer didn't send a certificate."));
		return NULL;
	}

	tmp = nussl_ssl_readable_dname(&sess->peer_cert->subj_dn);
	dn = strdup(tmp);
	nussl_free(tmp);
	return dn;
}
