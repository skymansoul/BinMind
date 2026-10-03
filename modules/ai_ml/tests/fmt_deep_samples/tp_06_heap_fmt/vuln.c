#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) void f(char *u){ char *b=malloc(64); if(!b)return; sprintf(b,"%s",u); printf(b); free(b); }
int main(void){ f("%s%s"); return 0; }
