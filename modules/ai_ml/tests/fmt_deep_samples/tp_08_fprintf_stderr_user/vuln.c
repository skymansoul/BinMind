#include <stdio.h>
__attribute__((noinline)) void f(char *u){ fprintf(stderr, u); }
int main(void){ f("%s"); return 0; }
