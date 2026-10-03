#include <stdio.h>
#include <stdlib.h>
int main(){unsigned s;scanf("%u",&s);char *b=malloc(s);free(b);return 0;}