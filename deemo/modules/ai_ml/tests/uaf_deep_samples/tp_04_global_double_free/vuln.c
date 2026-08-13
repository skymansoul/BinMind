#include <stdlib.h>
char *gd;
__attribute__((noinline)) void mk(void){ gd = malloc(8); }
__attribute__((noinline)) void f1(void){ free(gd); }
__attribute__((noinline)) void f2(void){ free(gd); }
int main(void){ mk(); f1(); f2(); return 0; }
