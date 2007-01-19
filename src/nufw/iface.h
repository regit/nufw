#ifndef IFACE_H
#define IFACE_H

int get_interface_information(struct queued_pckt* q_pckt, struct nfq_data *nfad);

int iface_table_open();
int iface_treat_message(int fd);

#endif
