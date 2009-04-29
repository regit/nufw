/*
 ** Copyright (C) 2007,2009 INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
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
#include "nufw.h"

#include <nubase.h>


#ifdef HAVE_NFQ_INDEV_NAME

/* mutex used to get around non thread-safeness of iface resolution
 * in libnfnetlink */
pthread_mutex_t iface_mutex;

int get_interface_information(struct nlif_handle *inst,
			      struct queued_pckt *q_pckt,
			      struct nfq_data *nfad)
{
	pthread_mutex_lock(&iface_mutex);
	nfq_get_indev_name(inst, nfad, q_pckt->indev);
	if (q_pckt->indev[0] == '*') {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				"Can not get indev information");
	}

	nfq_get_physindev_name(inst, nfad, q_pckt->physindev);
	if (q_pckt->physindev[0] == '*') {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				"Can not get physindev information");
	}

	nfq_get_outdev_name(inst, nfad, q_pckt->outdev);
	if (q_pckt->outdev[0] == '*') {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				"Can not get outdev information");
	} else {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				"Get outdev information: %s",
				q_pckt->outdev);
	}

	nfq_get_physoutdev_name(inst, nfad, q_pckt->physoutdev);
	if (q_pckt->physoutdev[0] == '*') {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				"Can not get physoutdev information");
	} else {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				"Get physoutdev information: %s",
				q_pckt->physoutdev);
	}
	pthread_mutex_unlock(&iface_mutex);
	return 1;
}

struct nlif_handle *iface_table_open()
{
	struct nlif_handle *inst;

	pthread_mutex_init(&iface_mutex, NULL);
	/* opening ifname resolution handle */
	inst = nlif_open();
	if (inst == NULL) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] Error during nlif_table_init()");
		return NULL;
	}
	nlif_query(inst);

	return inst;
}

int iface_treat_message(struct nlif_handle *inst)
{
	int ret;
	debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
			 "Network interface event");

	pthread_mutex_lock(&iface_mutex);
	ret = nlif_catch(inst);
	pthread_mutex_unlock(&iface_mutex);
	return ret;
}

void iface_table_close(struct nlif_handle *inst)
{
	debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
			 "Free iface resolution instance");
	nlif_close(inst);
}

#endif				/* #ifdef HAVE_NFQ_INDEV_NAME */
