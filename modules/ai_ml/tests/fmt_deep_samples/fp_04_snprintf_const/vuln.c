#include <stdio.h>
__attribute__((noinline)) void f(char *x){ char b[64]; snprintf(b, 64, "%s", x); }
int main(void){ f("a"); return 0; }
