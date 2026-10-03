#include <stdio.h>
#include <stdlib.h>
char *g;
int main(){g=malloc(256);free(g);if(g)printf("%s",g);return 0;}