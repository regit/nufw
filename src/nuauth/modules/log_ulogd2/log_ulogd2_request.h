/*
 ** Copyright(C) 2008 INL
 ** Written by  Pierre Chifflier <chifflier@inl.fr>
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

#ifndef __LOG_ULOGD2_REQUEST_H__
#define __LOG_ULOGD2_REQUEST_H__

#include "nubase.h"

enum ulogd2_option_type {
	ULOGD2_OPT_UNUSED = 0,
	ULOGD2_OPT_PREFIX,	/* log prefix (string) */
	ULOGD2_OPT_OOB_IN,	/* input device (string) */
	ULOGD2_OPT_OOB_OUT,	/* output device (string) */
	ULOGD2_OPT_OOB_TIME_SEC,	/* packet arrival time (u_int32_t) */

	/* NuFW specific options */
	ULOGD2_OPT_USER=200,	/* user name (string) */
	ULOGD2_OPT_USERID,	/* user id (u_int32_t) */
	ULOGD2_OPT_OSNAME,	/* OS name (string) */
	ULOGD2_OPT_OSREL,	/* OS release (string) */
	ULOGD2_OPT_OSVERS,	/* OS version (string) */
	ULOGD2_OPT_APPNAME,	/* application name (string) */
};

struct ulogd2_option {
	/* must come first */
	struct llist_head list;

	unsigned int opt;
	void * value;
	unsigned int length;
};

struct ulogd2_request {
/* fields to be sent to ulogd2 */
	unsigned int payload_len;
	unsigned char *payload;

	struct ulogd2_option *options;
};

struct ulogd2_request * ulogd2_request_new(void);

void ulogd2_request_set_payload(struct ulogd2_request *ur, unsigned char *payload, unsigned int payload_len);

void ulogd2_request_add_option(struct ulogd2_request *req, unsigned int opt, void *value, unsigned int length);

ssize_t ulogd2_request_format(struct ulogd2_request *ur, unsigned char *buf, unsigned int bufsz);

void ulogd2_request_free(struct ulogd2_request *ur);

#endif /* __LOG_ULOGD2_REQUEST_H__ */
