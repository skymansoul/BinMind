#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){char *b=malloc(96);free(b);char *c=malloc(96);memcpy(c,b,96);free(c);return 0;}
