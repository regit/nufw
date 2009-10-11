#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config-parser.h"
#include "config-table.h"

int assert_conf_vars(struct llist_head *l)
{
	char *var_str;

	/* var_redefined => "second" */
	var_str = nubase_config_table_get(l, "var_redefined");
	if (var_str == NULL || strcmp(var_str,"second") != 0) {
		fprintf(stderr, "Failed test: nubase_config_table_get(l, \"var_redefined\")\n");
		fprintf(stderr, "  var is '%s'\n", var_str);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct llist_head *l;

	char * srcdir;
	char conffile[1024];
#ifdef YYDEBUG
	extern int yydebug;
#endif

	srcdir = getenv("srcdir");
	if (srcdir == NULL)
		exit(1);

	sprintf(conffile, "%s/%s", srcdir, "t1.conf");

#ifdef YYDEBUG
	yydebug = 1;
#endif

	l = parse_configuration(conffile);
	if (l == NULL)
		exit(1);

	if (assert_conf_vars(l) != 0)
		exit(1);


	exit(0);
}
