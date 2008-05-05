#include <stdio.h>
#include <nubase.h>

int main(void)
{
	int i = 313445;
	char *str;

	str = (char *)str_itoa(i);
	printf("info:%s\n", str);

	free(str);

	return 0;
}

