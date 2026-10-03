#include <stdio.h>
__attribute__((noinline)) void f(int x){ fprintf(stdout, "log %d\n", x); }
int main(void){ f(1); return 0; }
