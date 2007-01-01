#include "nufw.h"

#ifdef USE_NFQUEUE
int get_interface_information(struct queued_pckt* q_pckt, struct nfq_data *nfad)
{
#ifdef HAVE_NFQ_GET_INDEV_NAME
	q_pckt->indev = nfq_get_indev_name(nfad);
	if (! q_pckt->indev){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get indev information");
	}

	q_pckt->physindev = nfq_get_physindev_name(nfad);
	if (! q_pckt->physindev){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get physindev information");
	}

	q_pckt->outdev = nfq_get_outdev_name(nfad);
	if (! q_pckt->outdev){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get outdev information");
	} else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Get outdev information: %s", q_pckt->outdev);
	}

	q_pckt->physoutdev = nfq_get_physoutdev_name(nfad);
	if (! q_pckt->physoutdev){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get physoutdev information");
	} else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Get physoutdev information: %s",q_pckt->physoutdev);
	}
#endif
	return 1;
}

#endif
