/*
 * Compile with  :
 * gcc -shared -o nobuffer.so interceptor.c
 */

#include <stdio.h>

#if defined(__GNUC__)
#  define CONSTRUCTOR __attribute__((constructor))
#else
#  define CONSTRUCTOR
#endif

CONSTRUCTOR void init()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

