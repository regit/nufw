#include <stdio.h>
#include <nubase.h>

int main(void)
{
	parse_configuration("../../../../conf/nuauth.conf");

	printf("nufw_gw_addr=[%s]\n", nubase_hash_get("nufw_gw_addr"));
	printf("foo=[%s]\n", nubase_hash_get("foo"));

	return 0;
}

