#include <stdio.h>
__attribute__((noinline)) void f(char *u, char *b){ snprintf(b, 64, u); }
int main(void){ char b[64]; f("%s", b); return 0; }
