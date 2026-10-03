#include <stdio.h>
__attribute__((noinline)) void f(int x){ printf("hello %d\n", x); }
int main(void){ f(7); return 0; }
