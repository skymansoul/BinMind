#include <stdio.h>
__attribute__((noinline)) void f(int x){ char *fmt="hello %d"; printf(fmt, x); }
int main(void){ f(7); return 0; }
