/*
** Copyright(C) 2008-2010 EdenWall Technologies
**          written by Pierre Chifflier <chifflier@edenwall.com>
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


#include <auth_srv.h>
#include <security.h>

#include "x509_ocsp.h"

/**
 *
 * \ingroup X509OSCPModule
 *
 * @{ */

#ifdef HAVE_OPENSSL

#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>

#define OCSP_BUFFER_LEN 256

#define OCSP_TIMEOUT 10

static X509* _read_cert_file(const char *cert_file)
{
	X509 *cert = NULL;
	FILE *fp = NULL;

	fp = fopen(cert_file,"rb");
	if (fp == NULL)
		return NULL;

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	return cert;
}

static int _extract_ocsp_uri(X509 *ca_cert, char *ocsp_host,
		char *ocsp_port_s, char *ocsp_path, int *ocsp_ssl)
{
	AUTHORITY_INFO_ACCESS *aia;
	int k, rc=-1;

	aia = (AUTHORITY_INFO_ACCESS *) X509_get_ext_d2i(ca_cert, NID_info_access, NULL, NULL);
	if ( aia == NULL) {
		return -1;
	}

	for (k=0;k<sk_ACCESS_DESCRIPTION_num(aia);k++) {
		ACCESS_DESCRIPTION *ad;
		GENERAL_NAME *gn;
		char *portPtr = NULL, *hostPtr = NULL, *pathPtr = "/";
		ASN1_IA5STRING *asn1Uri;
		int ssl;

		/* look for the OCSP info because AIA can have others */
		ad = sk_ACCESS_DESCRIPTION_value(aia, k);
		if (OBJ_obj2nid(ad->method) != NID_ad_OCSP)
			continue;

		/* make sure we have the URI */
		gn = ad->location;
		if (gn->type != GEN_URI)
			continue;
		asn1Uri = gn->d.uniformResourceIdentifier;
		log_message(DEBUG, DEBUG_AREA_MAIN,
				"Got URI %s", asn1Uri->data);

		if (! OCSP_parse_url((char*)asn1Uri->data, & hostPtr, & portPtr, & pathPtr, & ssl)) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					"OCSP_parse_url fails for \"%s\"", asn1Uri->data);
			continue;
		}

		SECURE_STRNCPY(ocsp_host, hostPtr, OCSP_BUFFER_LEN-1);
		SECURE_STRNCPY(ocsp_port_s, portPtr, OCSP_BUFFER_LEN-1);
		SECURE_STRNCPY(ocsp_path, pathPtr, OCSP_BUFFER_LEN-1);
		rc = 1;

		OPENSSL_free(hostPtr);
		OPENSSL_free(portPtr);
		OPENSSL_free(pathPtr);
		break;
	}

	AUTHORITY_INFO_ACCESS_free(aia);
	return (rc > 0);
}

static void fd_ready_to_write(int revents, void *arg)
{
	int *is_ready = arg;

	if (revents & EV_WRITE)
		{ /* fd might have data for us, joy! */ *is_ready = 1; }
	else if (revents & EV_TIMER)
		{ /* doh, nothing entered */ *is_ready = 0; }
}

static int wait_for_write(int fd)
{
	struct ev_loop *loop;
	int is_ready = 0;

	loop = ev_loop_new(0);
	ev_once (loop, fd, EV_WRITE, 10., fd_ready_to_write, &is_ready);

	ev_loop(loop, 0);
	ev_loop_destroy(loop);

	if (is_ready > 0)
		return 0;

	return -1;
}

static void fd_ready_to_read(int revents, void *arg)
{
	int *is_ready = arg;

	if (revents & EV_READ)
		{ /* fd might have data for us, joy! */ *is_ready = 1; }
	else if (revents & EV_TIMER)
		{ /* doh, nothing entered */ *is_ready = 0; }
}

static int wait_for_read(int fd)
{
	struct ev_loop *loop;
	int is_ready = 0;

	loop = ev_loop_new(0);
	ev_once (loop, fd, EV_READ, 10., fd_ready_to_read, &is_ready);

	ev_loop(loop, 0);
	ev_loop_destroy(loop);

	if (is_ready > 0)
		return 0;

	return -1;
}

static int nonblocking_read(int fd, void *buf, size_t count, unsigned int timeout)
{
	int ret;
	int read_count = 0;

	do {
		ret = wait_for_read(fd);
		if (ret < 0)
			return -1;

		ret = read(fd, buf, count);
		if (ret == -1) {
			if (errno == EINPROGRESS || errno == EWOULDBLOCK)
				continue;

			return -1;
		}
		read_count += ret;
	} while (ret < 0);

	return read_count;
}

static int nonblocking_write(int fd, void *buf, size_t count, unsigned int timeout)
{
	int ret;
	int write_count = 0;

	do {
		ret = write(fd, buf, count);
		if (ret == -1) {
			if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
				ret = wait_for_write(fd);
				if (ret < 0)
					return -1;
				ret = 0;
				continue;
			}
			log_message(WARNING, DEBUG_AREA_MAIN,
					" Fatal write error: %d (%s)\n", errno, strerror(errno));

			return -1;
		}
		write_count += ret;
	} while (ret < 0);

	return write_count;
}

static int ocsp_connect_client_socket(const char *ocsp_host, unsigned int ocsp_port)
{
	int sock;
	struct addrinfo *res, *res0;
	struct addrinfo hints;
	int ecode;
	int err;
	socklen_t optlen = sizeof(err);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	ecode = getaddrinfo(ocsp_host, NULL, &hints, &res0);
	if (ecode != 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not resolve OCSP server name %s: %s",
				ocsp_host, gai_strerror(ecode));
		return -1;
	}

	/* try all addresses */
	for (res=res0; res!=NULL; res=res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			continue;
		}

		/* set port number */
		if (res->ai_family == AF_INET) {
			struct sockaddr_in *in = (struct sockaddr_in*)res->ai_addr;
			in->sin_port = htons(ocsp_port);
		} else if (res->ai_family == AF_INET6) {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6*)res->ai_addr;
			in6->sin6_port = htons(ocsp_port);
		} else {
			continue;
		}

		/* set non-blocking mode */
		fcntl(sock,F_SETFL,(fcntl(sock,F_GETFL)|O_NONBLOCK));

		if (connect(sock, res->ai_addr, res->ai_addrlen) == 0)
			break;

		err = errno;
		if (err!=EINPROGRESS && err!=EWOULDBLOCK) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					" Connect failed: %d (%s) family:%d", err, strerror(err),
					res->ai_family);
			close(sock);
			continue;
		}
		/* wait for socket to be ready to write */
		ecode = wait_for_write(sock);
		if (ecode != 0) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					" Connect failed (timeout): family:%d",
					res->ai_family);
			close(sock);
			continue;
		}

		/* make sure socket is connected */
		if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &optlen)) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					" Could not retrieve the error code");
			close(sock);
			continue;
		}
		if (err == 0) {
			break;
		} else {
			log_message(WARNING, DEBUG_AREA_MAIN,
					" Connect failed (getsockopt): %d (%s) family:%d", err, strerror(err),
					res->ai_family);
		}
	}

	freeaddrinfo(res0);

	if (res == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not create a valid connection to OCSP server %s:%d",
				ocsp_host, ocsp_port);

		return -1;
	}

	return sock;
}

/* Serialize an OCSP request which will be sent to the responder at
 * given URI to a memory BIO object, which is returned. */
static BIO *serialize_request(OCSP_REQUEST *req, const char *ocsp_path, const char *ocsp_host, unsigned int ocsp_port)
{
	BIO *bio;
	int len;

	len = i2d_OCSP_REQUEST(req, NULL);

	bio = BIO_new(BIO_s_mem());

	BIO_printf(bio, "POST %s HTTP/1.0\r\n"
			"Host: %s:%d\r\n"
			"Content-Length: %d\r\n"
			"\r\n",
			ocsp_path,
			ocsp_host, ocsp_port, len);

	if (i2d_OCSP_REQUEST_bio(bio, req) != 1) {
		BIO_free(bio);
		return NULL;
	}

	return bio;
}

static int _ocsp_send_request(BIO *request, int sock)
{
	char buf[4096];
	int len;
	int rc;

	while ((len = BIO_read(request, buf, sizeof(buf))) > 0) {
		rc = nonblocking_write(sock, buf, len, OCSP_TIMEOUT);

		if (rc < 0) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					" _ocsp_send_request: %d (%s)", errno, strerror(errno));
			return -1;
		}
	}

	return 0;
}

static OCSP_RESPONSE *_ocsp_read_response(BIO *bio, int sock)
{
	char buf[8192];
	int len;
	OCSP_RESPONSE *response = NULL;
	char *ptr;
	int headers_found = 0;

	while ((len = nonblocking_read(sock, buf, sizeof(buf), OCSP_TIMEOUT)) > 0) {
		if (len < 0) {
			return NULL;
		}
		buf[len] = '\0';

		/* Skip headers; don't have to even bother parsing the
		 * Content-Length since the server is obliged to close the
		 * connection after the response anyway for HTTP/1.0. */
		/* read until empty line (including this line) */

		if (headers_found) {
			BIO_write(bio, buf, (int)len);
		} else {
			ptr = buf;
			do {
				ptr = strchr(ptr, '\n');
				if (ptr == NULL)
					continue;
				ptr++;
				if (ptr[0] == '\r' || ptr[0] == '\n') {
					/* empty line: end of headers */
					ptr = strchr(ptr, '\n');
					ptr++;
					if (ptr == NULL) {
						/* this should never happen */
						continue;
					}
					BIO_write(bio, ptr, (int)len - (ptr-buf));
					headers_found = 1;
				}
			} while(ptr != NULL && headers_found == 0);
		}
	}

	/* decode the OCSP response the bio */
	response = d2i_OCSP_RESPONSE_bio(bio, NULL);
	if (response == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"failed to decode OCSP response data");
	}

	return response;
}

OCSP_RESPONSE *handle_ocsp_request(OCSP_REQUEST *request, int sock, const char *ocsp_path, const char *ocsp_host, unsigned int ocsp_port)
{
	OCSP_RESPONSE *response = NULL;
	BIO *bio;
	int rc;

	bio = serialize_request(request, ocsp_path, ocsp_host, ocsp_port);
	if (bio == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not serialize OCSP request");
		return NULL;
	}

	/* send serialized request */
	rc = _ocsp_send_request(bio, sock);
	if (rc != 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not send OCSP request");
		BIO_free(bio);
		return NULL;
	}

	 /* Clear the BIO contents, ready for the response. */
	(void)BIO_reset(bio);

	/* read response */
	response = _ocsp_read_response(bio, sock);

	BIO_free(bio);
	return response;
}

/** See RFC 2459
 */
int check_ocsp(nussl_session *session, gpointer params_p)
{
	int retval = 1;
	int ret;
	int fd = -1;
	struct x509_ocsp_params *params = (struct x509_ocsp_params *)params_p;
	char ocsp_host[OCSP_BUFFER_LEN];
	char ocsp_port_s[OCSP_BUFFER_LEN];
	char ocsp_path[OCSP_BUFFER_LEN];
	int ocsp_ssl = 0;
	unsigned int ocsp_port;
	BIO *bio=NULL;
	SSL *ssl = (SSL*)nussl_get_socket(session);
	SSL_CTX *ctx = (SSL_CTX*)nussl_get_ctx(session);
	X509 *cert;
	X509 *cacert;
	STACK_OF(X509) *cas = NULL;
	STACK_OF(X509_NAME) *cert_stack;
	X509 *issuer = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX store_ctx;
	unsigned long ocsp_flags;
	OCSP_CERTID *certID;
	OCSP_REQUEST *request=NULL;
	OCSP_RESPONSE *response=NULL;
	OCSP_BASICRESP *basicResponse=NULL;
	ASN1_GENERALIZEDTIME *produced_at, *this_update, *next_update;
	int status, reason;

	/* XXX this will read only the first certificate from the CA file */
	cacert = _read_cert_file(params->ca);
	if (cacert == NULL) {
		log_message(CRITICAL, DEBUG_AREA_MAIN,
				" Could not read CA file %s", params->ca);
		return -1;
	}

	retval = 0;
	if (params->ocsp_ca_use_aia) {
		/* this needs to be done for each different CA */
		retval = _extract_ocsp_uri(cacert,
				ocsp_host,
				ocsp_port_s,
				ocsp_path,
				&ocsp_ssl);
	}

	if (retval > 0) {
		ocsp_port = (unsigned int)strtoul(ocsp_port_s, NULL, 10);
	} else {
		/* check if an OCSP server was configured */
		if (params->ocsp_server == NULL)
			return 0;

		SECURE_STRNCPY(ocsp_host, params->ocsp_server, OCSP_BUFFER_LEN);
		ocsp_port = params->ocsp_port;
		SECURE_STRNCPY(ocsp_path, params->ocsp_path, OCSP_BUFFER_LEN);
	}

	log_message(DEBUG, DEBUG_AREA_MAIN,
		" Checking OCSP status on [%s:%d %s]",
		ocsp_host, ocsp_port, ocsp_path);

	fd = ocsp_connect_client_socket(ocsp_host, ocsp_port);
	if (fd < 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not connect to OCSP server %s", ocsp_host);
		goto cleanup;
	}



	log_message(DEBUG, DEBUG_AREA_MAIN,
			" Connected to OCSP server %s", ocsp_host);

	cert = SSL_get_peer_certificate(ssl);
	cert_stack = (STACK_OF(X509) *)SSL_get_peer_cert_chain(ssl);

	if (cert == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get client certificate");
		goto cleanup;
	}

	store = SSL_CTX_get_cert_store(ctx);

	X509_STORE_CTX_init (&store_ctx, store, cert, cert_stack);

	ret = X509_STORE_add_cert(store, cacert);

	if (X509_STORE_CTX_get1_issuer(&issuer, &store_ctx, cert)!=1) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get issuer");
		goto cleanup;
	}

	/* get current certificate ID */
	certID=OCSP_cert_to_id(0, cert, issuer);
	if (certID == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get certificate ID for OCSP request");
		goto cleanup;
	}

	request=OCSP_REQUEST_new();
	if (!request) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not allocate OCSP request");
		goto cleanup;
	}

	if (!OCSP_request_add0_id(request, certID)) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not add cert ID to OCSP request");
		goto cleanup;
	}
	OCSP_request_add1_nonce(request, 0, -1);

	/* send the request and get a response */
	response = handle_ocsp_request(request, fd, ocsp_path, ocsp_host, ocsp_port);
	if (response == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get OCSP response");
		goto cleanup;
	}

	close(fd);
	fd = -1;

	ret = OCSP_response_status(response);
	if (ret != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"Responder Error: %s (%d)",
				OCSP_response_status_str(ret), ret);
		goto cleanup;
	}

	log_message(DEBUG, DEBUG_AREA_MAIN,
			"OCSP response received");


	/* verify the response */
	basicResponse = OCSP_response_get1_basic(response);
	if (!basicResponse) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get OCSP basic response");
		goto cleanup;
	}
	if (OCSP_check_nonce(request, basicResponse)<=0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get OCSP basic response OCSP_check_nonce)");
		goto cleanup;
	}
	cas = sk_X509_new_null();
	sk_X509_push(cas, cacert);
	ocsp_flags = OCSP_NOCHAIN | OCSP_NOEXPLICIT | OCSP_TRUSTOTHER;
	//ocsp_flags = 0xffff;
	ret = OCSP_basic_verify(basicResponse, cas, store,
				ocsp_flags /*-1*/ /* FIXME: be 0 */);
	if ( ret <= 0 ) {
		unsigned long errcode;
		const char * err_reason;

		log_message(WARNING, DEBUG_AREA_MAIN,
				" OCSP response verification failed (%d)",
				ret);
		while ((errcode = ERR_get_error()) != 0) {
			err_reason = ERR_reason_error_string(errcode);
			log_message(WARNING, DEBUG_AREA_MAIN,
					"\terr: %s (%lu)",
					(char *)err_reason,
					errcode & 0xff);

		}
	}
	if (OCSP_resp_find_status(basicResponse, certID, &status, &reason,
				&produced_at, &this_update, &next_update)==0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				" Could not get OCSP basic response (OCSP_resp_find_status)");
		OCSP_RESPONSE_free(response);
	}

	/* success */
	log_message(DEBUG, DEBUG_AREA_MAIN,
			"OCSP verification status= %s (%d)",
			OCSP_cert_status_str(status),
			status);


	X509_STORE_CTX_cleanup (&store_ctx);

	retval = status;

cleanup:
	if (bio)
		BIO_free_all(bio);
	if (issuer)
		X509_free(issuer);
	if (cas)
		sk_pop_free(cas, (void (*)(void *))X509_free);
	if (request)
		OCSP_REQUEST_free(request);
	if (response)
		OCSP_RESPONSE_free(response);
	if (basicResponse)
		OCSP_BASICRESP_free(basicResponse);
	if (fd >= 0)
		close(fd);

	return retval;
}

#else /* HAVE_OPENSSL */

int check_ocsp(nussl_session *session, gpointer params_p)
{
#warning "check_ocsp is not supported for this SSL implementation"
	return 0;
}

#endif /* HAVE_OPENSSL */

/** @} */
