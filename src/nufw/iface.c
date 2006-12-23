
int set_iface_name(u_int32_t iface,char* ifacename)
{

}


int get_interface_information(struct queued_pckt* q_pckt, struct nfq_data *nfad)
{
	u_int32_t iface;
	iface = nfq_get_indev(nfad);
	if (! set_iface_name(iface,q_pckt->indev)){
		return 0;
	}

	iface = nfq_get_physindev(nfad);
	if (! set_iface_name(iface,q_pckt->physindev)){

		return 0;
	}

	iface = nfq_get_outdev(nfad);
	if (! set_iface_name(iface,q_pckt->outdev)){
		return 0;
	}

	iface = nfq_get_physoutdev(nfad);
	if (! set_iface_name(iface,q_pckt->physoutdev)){
		return 0;
	}

	return 1;
}
