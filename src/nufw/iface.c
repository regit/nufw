#include "nufw.h"

#ifdef USE_NFQUEUE
int get_interface_information(struct nlif_handle *inst, struct queued_pckt* q_pckt, struct nfq_data *nfad)
{
#ifdef HAVE_NLIF_CATCH
	nfq_get_indev_name(inst, nfad, q_pckt->indev);
	if (q_pckt->indev[0] == '*') {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get indev information");
	}

	nfq_get_physindev_name(inst, nfad, q_pckt->physindev);
	if (q_pckt->physindev[0] == '*') {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get physindev information");
	}

	nfq_get_outdev_name(inst, nfad, q_pckt->outdev);
	if (q_pckt->outdev[0] == '*') {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get outdev information");
	} else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Get outdev information: %s", q_pckt->outdev);
	}

	nfq_get_physoutdev_name(inst, nfad, q_pckt->physoutdev);
	if (q_pckt->physoutdev[0] == '*') {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Can not get physoutdev information");
	} else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Get physoutdev information: %s",q_pckt->physoutdev);
	}
#else
	q_pckt->indev[0] = '*';
	q_pckt->outdev[0] = '*';
	q_pckt->physindev[0] = '*';
	q_pckt->physoutdev[0] = '*';
#endif
	return 1;
}

#ifdef HAVE_NLIF_CATCH
struct nlif_handle *iface_table_open()
{
    struct nlif_handle *inst;
    /* opening ifname resolution handle */
    inst = nlif_open();
    if (inst == NULL) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "[!] Error during nlif_table_init()");
        return NULL;
    }
    nlif_query(inst);

    return inst;
}

int iface_treat_message(struct nlif_handle *inst)
{
   debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
		"Network interface event");
   return nlif_catch(inst);
}

void iface_table_close(struct nlif_handle *inst)
{
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
		"Free iface resolution instance");
	nlif_close(inst);
}

#endif   /* #ifdef HAVE_NLIF_CATCH */
#endif   /* #ifdef USE_NFQUEUE */

