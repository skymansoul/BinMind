#include <stdio.h>
__attribute__((noinline)) void f(char *s){ const char *fmt="%s"; printf(fmt, s); }
int main(void){ f("a"); return 0; }
