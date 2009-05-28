/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_WORKER_H__
#define __EMC_WORKER_H__

#include <config.h>

#include <glib.h>

void emc_worker_tls_handshake(gpointer userdata, gpointer data);

void emc_worker_reader(gpointer userdata, gpointer data);

void emc_client_cb (struct ev_loop *loop, ev_io *w, int revents);

#endif /* __EMC_WORKER_H__ */
