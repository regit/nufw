/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_CONFIG_H__
#define __EMC_CONFIG_H__

#define EMC_DEFAULT_CONF	CONFIG_DIR "/emc.conf"

/** \brief Default port EMC will listen to
 */
#define EMC_DEFAULT_PORT	"4140"

/** \brief Default value for maximum number of worker threads.
 */
#define EMC_DEFAULT_MAX_WORKERS	32

int emc_init_config(const char *filename);

char *emc_config_table_get(const char *key);
char *emc_config_table_get_alwaysstring(char *key);
char *emc_config_table_get_or_default(char *key, char *replace);
int emc_config_table_get_or_default_int(char *key, int defint);
void emc_config_table_destroy(void);

#endif /* __EMC_CONFIG_H__ */
