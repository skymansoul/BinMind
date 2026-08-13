#include <stdio.h>
__attribute__((noinline)) void f(int i, char *s){ printf("%d %s", i, s); }
int main(void){ f(1, "x"); return 0; }
