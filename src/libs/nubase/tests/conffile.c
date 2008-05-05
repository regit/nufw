#include <stdio.h>
#include <nubase.h>

int conf_get_int_default(char *key, int defint)  
{
	char *str;								
	int i;

	str = nubase_config_table_get_or_default(key, str_itoa(defint));
	printf("string=%s\n", str);

	i = atoi(str);								

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

	printf("foo or default=[%s]\n", nubase_config_table_get_or_default("foo", "bar"));
	printf("foo or default int=[%s]\n", nubase_config_table_get_or_default("foo", str_itoa(42)));

	i = conf_get_int_default("nuauth_number_aclcheckers", 42);
	printf("integer value:%d\n", i);

	return 0;
}

