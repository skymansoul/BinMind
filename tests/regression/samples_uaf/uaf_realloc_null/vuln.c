#include <stdio.h>
#include <stdlib.h>
int main(){char *p=malloc(64);char *q=realloc(p,0);puts(q);return 0;}
