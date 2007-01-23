#ifndef IFACE_H
#define IFACE_H

int get_interface_information(struct nlif_inst *inst, 
                struct queued_pckt* q_pckt, struct nfq_data *nfad);

struct nlif_inst *iface_table_open();
int iface_treat_message(struct nlif_inst *inst);

void iface_table_close(struct nlif_inst *inst);

#endif
