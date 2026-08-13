#include <stdio.h>
__attribute__((noinline)) void f(char *u){ fprintf(stdout, u); }
int main(void){ f("%x"); return 0; }
