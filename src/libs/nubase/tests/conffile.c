#include <stdio.h>
#include <nubase.h>

int conf_get_int_default(key,defint)  
{
	char *str;								
	int i;

	str = nubase_config_table_get_or_default(key, str_itoa(defint));

	i = str_itoa(str);								
	free(str);								
	return i;
}

int main(void)
{
	int i;

	parse_configuration("../../../../conf/nuauth.conf");

	printf("nufw_gw_addr=[%s]\n", nubase_config_table_get("nufw_gw_addr"));
	nubase_config_table_set("nufw_gw_addr", "in the navy");
	printf("nufw_gw_addr=[%s]\n", nubase_config_table_get("nufw_gw_addr"));
	printf("foo=[%s]\n", nubase_config_table_get("foo"));

	i = conf_get_int_default("nuauth_number_aclcheckers", 42);
	printf("integer value:%d\n", i);

	return 0;
}

