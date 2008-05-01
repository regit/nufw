/*
 ** Copyright 2005 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
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

#include "nufw_source.h"
#include "libnuclient.h"
#include <sasl/saslutil.h>
#include <nussl.h>
#include <proto.h>
#include "proc.h"
#include "checks.h"
#include "tcptable.h"
#include "sending.h"

/** \addtogroup libnuclient
 * @{
 */

/**
 * Thread waiting for nuauth message to do client tasks
 *
 * Message from nuauth :
 * - SRV_REQUIRED_PACKET : awake nu_client_thread_check
 * - SRV_REQUIRED_HELLO : send hello back to nuauth
 */

nu_error_t recv_message(nuauth_session_t *session, nuclient_error_t *err)
{
	int ret;
	char dgram[512];
	const size_t message_length =
	    sizeof(struct nu_header) + sizeof(struct nu_authfield_hello) +
	    sizeof(struct nu_authreq);
	char message[message_length];
	struct nu_header *header;
	struct nu_authreq *authreq;
	struct nu_authfield_hello *hellofield;

	/* fill struct */
	header = (struct nu_header *) message;
	header->proto = PROTO_VERSION;
	header->msg_type = USER_REQUEST;
	header->option = 0;
	header->length = htons(message_length);

	authreq = (struct nu_authreq *) (header + 1);
	authreq->packet_seq = session->packet_seq++;
	authreq->packet_length =
		htons(sizeof(struct nu_authreq) +
				sizeof(struct nu_authfield_hello));

	hellofield = (struct nu_authfield_hello *) (authreq + 1);
	hellofield->type = HELLO_FIELD;
	hellofield->option = 0;
	hellofield->length = htons(sizeof(struct nu_authfield_hello));

	ret = nussl_read(session->nussl, dgram, sizeof dgram);

	if (ret == NUSSL_SOCK_TIMEOUT) {
		SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
		return NU_EXIT_CONTINUE;
	}

	if (ret <= 0) {
		ask_session_end(session);
		SET_ERROR(err, INTERNAL_ERROR, SESSION_NOT_CONNECTED_ERR);
		return NU_EXIT_ERROR;
	}

	switch (dgram[0]) {
		case SRV_REQUIRED_PACKET:
			if (session->debug_mode) {
				printf("[+] Client is asked to send new connections.\n");
			}
			nu_client_real_check(session, err);
			break;

		case SRV_REQUIRED_HELLO:
			hellofield->helloid =
				((struct nu_srv_helloreq *) dgram)->helloid;
			if (session->debug_mode) {
				printf("[+] Send HELLO\n");
			}

			/*  send it */
			ret = nussl_write(session->nussl, message, message_length);
			if (ret < 0) {
#if DEBUG_ENABLE
				printf("write failed at %s:%d\n",
						__FILE__, __LINE__);
#endif
				ask_session_end(session);
				SET_ERROR(err, INTERNAL_ERROR, SESSION_NOT_CONNECTED_ERR);
				return NU_EXIT_ERROR;
			}
			break;

		default:
			printf("unknown message\n");
			return NU_EXIT_CONTINUE;
	}
	return NU_EXIT_OK;
}

nu_error_t increase_refresh_delay(nuauth_session_t *session)
{
	if (session->sleep_delay.tv_sec * 1000000 + 
		session->sleep_delay.tv_usec <
		session->max_sleep_delay.tv_sec * 1000000 +
		session->max_sleep_delay.tv_usec) {
		session->sleep_delay.tv_sec = session->sleep_delay.tv_sec * 2 +
			    (session->sleep_delay.tv_usec * 2) / 1000000;
		session->sleep_delay.tv_usec =
			session->sleep_delay.tv_usec * 2 % 1000000;
		/* Should retest: We may exceed max delay if we don't have 
		 * max_delay=min_delay*2^k */
	}
	return NU_EXIT_OK;
}

nu_error_t reset_refresh_delay(nuauth_session_t *session)
{
	session->sleep_delay.tv_sec = session->min_sleep_delay.tv_sec;
	session->sleep_delay.tv_usec = session->min_sleep_delay.tv_usec;
	return NU_EXIT_OK;
}

/**
 * \ingroup nuclientAPI
 * \brief Function called by client to initiate a check
 *
 * It has to be run at regular interval :
 *  - In POLL mode, it is really doing the job.
 *  - In PUSH mode, it is used to detect failure and send HELLO message
 *
 * \param session A pointer to a valid ::nuauth_session_t session
 * \param err A pointer to a allocated ::nuclient_error_t
 * \return -1 if a problem occurs. Session is destroyed if nu_client_check() return -1;
 *
 * \par Internal
 * It is in charge of cleaning session as the session may be used
 * by user and we have no control of it. It has to be called for the first
 * time AFTER all forks occurs to create the working threads. This is
 * mandatory and occurs because fork does not replicate the threads.
 *
 *  - Poll mode: this is just a wrapper to nu_client_real_check()
 *  - Push mode: It is used to send HELLO message
 *
 * \return Returns -1 on error, 1 otherwise
 */
int nu_client_check(nuauth_session_t * session, nuclient_error_t * err)
{
	/* test is a thread has detected problem with the session */
	if (session->connected == 0) {
		SET_ERROR(err, INTERNAL_ERROR, SESSION_NOT_CONNECTED_ERR);
		return -1;
	}

	if (session->server_mode == SRV_TYPE_POLL) {
		int checkreturn;

		usleep(session->sleep_delay.tv_sec * 1000000 +
		       session->sleep_delay.tv_usec);
		checkreturn = nu_client_real_check(session, err);
		if (checkreturn < 0) {
			/* error code filled by nu_client_real_check() */
			return -1;
		} else {
			SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
			return 1;
		}
	} else {
		struct timeval tv;	
		fd_set select_set;
		int ret;
		tv.tv_sec = session->sleep_delay.tv_sec;
		tv.tv_usec = session->sleep_delay.tv_usec;

		if (session->nussl == NULL) {
			SET_ERROR(err, INTERNAL_ERROR, UNKNOWN_ERR);
			return -1;
		}
		/* Going to wait an event */
		FD_ZERO(&select_set);
		FD_SET(nussl_session_get_fd(session->nussl), &select_set);
		ret = select(nussl_session_get_fd(session->nussl)+1, &select_set, NULL, NULL, &tv);

		/* catch select() error */
		if (ret == -1) {
			ask_session_end(session);
			SET_ERROR(err, INTERNAL_ERROR, SESSION_NOT_CONNECTED_ERR);
			return -1;
		}

		if (ret == 0) {
			int checkreturn;
			/* start a check */
			checkreturn = nu_client_real_check(session, err);
			if (checkreturn < 0) {
				/* error code filled by nu_client_real_check() */
				return -1;
			} else {
				SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
				if (checkreturn == 0) {
					increase_refresh_delay(session);
				}
				return 1;
			}
			/* sending hello if needed */
			if ((time(NULL) - session->timestamp_last_sent) >
					SENT_TEST_INTERVAL) {
				if (!send_hello_pckt(session)) {
					SET_ERROR(err, INTERNAL_ERROR,
							TIMEOUT_ERR);
					return -1;
				}
				session->timestamp_last_sent = time(NULL);
			}
		} else {
			if (recv_message(session, err) == NU_EXIT_ERROR) {
				return -1;
			}
		}
	}
	SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
	return 1;
}

/**
 * Function that check connections table and send authentication packets:
 *    - Read the list of connections and build a conntrack table
 *      (call to tcptable_read()) ;
 *    - Initialize program list (/proc/ reading) ;
 *    - Compare current table with old one (compare call) ;
 *    - Free and return.
 *
 * \return Number of authenticated packets, or -1 on failure
 */
int nu_client_real_check(nuauth_session_t * session, nuclient_error_t * err)
{
	conntable_t *new;
	int nb_packets = 0;

	if (session->debug_mode) {
		printf("[+] Client checking for new connections.\n");
	}

	if (tcptable_init(&new) == 0) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		return -1;
	}
	if (tcptable_read(session, new) == 0) {
		SET_ERROR(err, INTERNAL_ERROR, TCPTABLE_ERR);
		return -1;
	}
#ifdef LINUX
	/* update cache for link between proc and socket inode */
	prg_cache_load();
#endif
	nb_packets = compare(session, session->ct, new, err);
	/* free link between proc and socket inode */
#ifdef LINUX
	prg_cache_clear();
#endif

	tcptable_free(session->ct);

	/* on error, we ask client to exit */
	if (nb_packets < 0) {
		ask_session_end(session);
		return nb_packets;
	}
	session->ct = new;

	if (nb_packets > 0) {
		reset_refresh_delay(session);
	}
	return nb_packets;
}


/** @} */
