#include <stdio.h>
__attribute__((noinline)) void w(char *u){ printf(u); }
int main(void){ w("%n"); return 0; }
