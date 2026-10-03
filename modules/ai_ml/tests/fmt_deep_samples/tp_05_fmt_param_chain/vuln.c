#include <stdio.h>
__attribute__((noinline)) void f(char *u){ char *v = u; printf(v); }
int main(void){ f("%s"); return 0; }
