#ifndef IFACE_H
#define IFACE_H

int get_interface_information(struct nlif_handle *inst, 
                struct queued_pckt* q_pckt, struct nfq_data *nfad);

struct nlif_handle *iface_table_open();
int iface_treat_message(struct nlif_handle *inst);

void iface_table_close(struct nlif_handle *inst);

#endif
