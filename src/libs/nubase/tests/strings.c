#include <stdio.h>
#include <nubase.h>

int main(void)
{
	char *str;

	str = str_itoa(-12345);

	printf("info:[%s]\n", str);

	free(str);

	return 0;
}

