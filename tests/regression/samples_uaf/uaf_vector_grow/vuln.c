#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() { char **items = malloc(4*sizeof(char*));
items[0]=strdup("a");items[1]=strdup("b");
char **n = realloc(items,8*sizeof(char*));
items[2]=strdup("c"); free(n); return 0; }
