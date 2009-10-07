/*
 ** Copyright(C) 2008-2009 INL
 ** Written by  Pierre Chifflier <chifflier@inl.fr>
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

#ifndef __LOG_ULOGD2_H__
#define __LOG_ULOGD2_H__

struct log_ulogd2_params {
	char *path;
	int fd;
};

#define DEFAULT_ULOGD2_SOCKET "/var/run/ulogd2.sock"

#include "log_ulogd2_request.h"

#endif /* __LOG_ULOGD2_H__ */
