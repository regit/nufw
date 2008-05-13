#include <stdio.h>
#include <nubase.h>

int conf_get_int_default(char *key, int defint)
{
	char *str, *tmp;
	int i;

	tmp = str_itoa(defint);
	str = nubase_config_table_get_or_default(key, tmp);
	free(tmp);
	printf("string=%s\n", str);

	i = atoi(str);

	free(str);

	return i;
}

int main(void)
{
	int i;
	char *s;

	parse_configuration("../../../../conf/nuauth.conf");

	printf("nufw_gw_addr=[%s]\n", nubase_config_table_get("nufw_gw_addr"));
	nubase_config_table_set("nufw_gw_addr", "in the navy");
	printf("nufw_gw_addr=[%s]\n", nubase_config_table_get("nufw_gw_addr"));
	printf("foo=[%s]\n", nubase_config_table_get("foo"));

	s = nubase_config_table_get_or_default("foo", "bar");
	printf("foo or default=[%s]\n", s);
	free(s);
	i = conf_get_int_default("foo", 42);
	printf("foo or default int=[%d]\n", i);

	i = conf_get_int_default("nuauth_number_aclcheckers", 42);
	printf("integer value:%d\n", i);

	nubase_config_table_destroy();

	return 0;
}

