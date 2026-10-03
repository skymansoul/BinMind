#include <stdio.h>
__attribute__((noinline)) void log_fmt(char *u){ printf(u); }
int main(void){ log_fmt("%s"); return 0; }
