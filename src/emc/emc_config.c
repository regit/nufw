/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#include <config.h>

#include <unistd.h>
#include <string.h>

#include <nubase.h>
#include <config-parser.h>

#include "emc_server.h"
#include "emc_config.h"

static struct llist_head *emc_config_table_list = NULL;

int emc_init_config(const char *filename)
{
	struct llist_head *new_config;

	new_config = parse_configuration(filename);
	if (new_config == NULL)
		return -1;

	if (emc_config_table_list != NULL)
		emc_config_table_destroy();

	emc_config_table_list = new_config;

	return 0;
}

char *emc_config_table_get(const char *key)
{
	return nubase_config_table_get(emc_config_table_list, key);
}

char *emc_config_table_get_alwaysstring(char *key)
{
	return nubase_config_table_get_alwaysstring(emc_config_table_list, key);
}

char *emc_config_table_get_or_default(char *key, char *replace)
{
	return nubase_config_table_get_or_default(emc_config_table_list, key, replace);
}

int emc_config_table_get_or_default_int(char *key, int defint)
{
	return nubase_config_table_get_or_default_int(emc_config_table_list, key, defint);
}

void emc_config_table_destroy(void)
{
	nubase_config_table_destroy(emc_config_table_list);
	emc_config_table_list = NULL;
}


