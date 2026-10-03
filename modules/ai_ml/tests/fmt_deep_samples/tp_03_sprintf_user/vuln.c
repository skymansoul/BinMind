#include <stdio.h>
__attribute__((noinline)) void f(char *u, char *b){ sprintf(b, u); }
int main(void){ char b[128]; f("%s", b); return 0; }
