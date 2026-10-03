#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* heap_overflow_08 - memmove overlapping regions */
int main(){char*p=malloc(64);memmove(p+32,p,64);free(p);return 0;}
