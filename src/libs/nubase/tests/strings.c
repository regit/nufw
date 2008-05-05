#include <stdio.h>
#include <nubase.h>

int main(void)
{
	char *str;
	int i = -12345;

	str = str_itoa(i);

	printf("input=[%d],output=[%s]\n", i, str);

	free(str);

	return 0;
}

