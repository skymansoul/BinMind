#include <stdlib.h>
char *gp;
__attribute__((noinline)) void f(void){ gp = malloc(16); }
__attribute__((noinline)) void g(void){ free(gp); }
__attribute__((noinline)) void h(void){ if (gp) gp[0] = 1; }
int main(void){ f(); g(); h(); return 0; }
