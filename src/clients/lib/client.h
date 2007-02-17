/*
 ** Copyright 2005 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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


#ifndef CLIENT_H
#define CLIENT_H

#define SENT_TEST_INTERVAL 30

#include <config.h>
#include "libnuclient.h"
#include "proc.h"
#include "tcptable.h"
#include "checks.h"
#include "sending.h"

char *locale_to_utf8(char *inbuf);

#define SET_ERROR(ERR, FAMILY, CODE) \
        if (ERR != NULL) \
        { \
            ERR->family = FAMILY; \
            ERR->error = CODE; \
        }

#endif
