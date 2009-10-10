#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config-parser.h"
#include "config-table.h"

int assert_conf_vars(struct llist_head *l)
{
	char *var_str;
	int var_int;

	/* var_str => "str" */
	var_str = nubase_config_table_get(l, "var_str");
	if (var_str == NULL || strcmp(var_str,"str") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get(l, \"var_str\")\n");
		return 1;
	}

	/* var_int => "42" */
	var_str = nubase_config_table_get(l, "var_int");
	if (var_str == NULL || strcmp(var_str,"42") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get(l, \"var_int\")\n");
		return 1;
	}

	/* var_int => "42" */
	var_str = nubase_config_table_get_alwaysstring(l, "var_int");
	if (var_str == NULL || strcmp(var_str,"42") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get_alwaysstring(l, \"var_int\")\n");
		return 1;
	}

	/* var_int => 42 */
	var_int = nubase_config_table_get_or_default_int(l, "var_int", -1);
	if (var_int < 0 || var_int != 42) {
		fprintf(stderr, "Failed test: nubase_config_table_get_or_default_int(l, \"var_int\", -1)\n");
		return 1;
	}

	/* var_does_not_exist => NULL */
	var_str = nubase_config_table_get(l, "var_does_not_exist");
	if (var_str != NULL) {
		fprintf(stderr, "Failed test: nubase_config_table_get(l, \"var_does_not_exist\")\n");
		return 1;
	}

	/* var_does_not_exist => "default" */
	var_str = nubase_config_table_get_or_default(l, "var_does_not_exist", "default");
	if (var_str == NULL || strcmp(var_str,"default") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get_or_default(l, \"var_does_not_exist\", \"default\")\n");
		return 1;
	}

	/* var_str_included => "str" */
	var_str = nubase_config_table_get(l, "var_str_included");
	if (var_str == NULL || strcmp(var_str,"str") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get(l, \"var_str_included\")\n");
		return 1;
	}

#if 0
	/* var_str_with_comment => "str" */
	var_str = nubase_config_table_get(l, "var_str_with_comment");
	if (var_str == NULL || strcmp(var_str,"str") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get(l, \"var_str_with_comment\")\n");
		fprintf(stderr, "var_str: %s\n", var_str);
		return 1;
	}
#endif

	return 0;
}

int main(int argc, char **argv)
{
	struct llist_head *l;

	char * srcdir;
	char conffile[1024];

	srcdir = getenv("srcdir");
	if (srcdir == NULL)
		exit(1);

	sprintf(conffile, "%s/%s", srcdir, "t1.conf");

	l = parse_configuration(conffile);
	if (l == NULL)
		exit(1);

	if (assert_conf_vars(l) != 0)
		exit(1);


	exit(0);
}
