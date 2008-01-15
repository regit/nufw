/*
 ** Copyright (C) 2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
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


#include "nufw.h"

#ifdef HAVE_NFQ_INDEV_NAME
int get_interface_information(struct nlif_handle *inst,
			      struct queued_pckt *q_pckt,
			      struct nfq_data *nfad)
{
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
	return 1;
}

struct nlif_handle *iface_table_open()
{
	struct nlif_handle *inst;
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
	debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
			 "Network interface event");
	return nlif_catch(inst);
}

void iface_table_close(struct nlif_handle *inst)
{
	debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
			 "Free iface resolution instance");
	nlif_close(inst);
}

#endif				/* #ifdef HAVE_NFQ_INDEV_NAME */
