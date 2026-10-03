#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void logit(char *s) { puts(s); }
int main() { char *b=malloc(128); strcpy(b,"data"); free(b); logit(b); return 0; }
