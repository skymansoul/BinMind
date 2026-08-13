#include <stdlib.h>
char *gp;
__attribute__((noinline)) void consume(char *p){ if (p) p[0] = 1; }
__attribute__((noinline)) void mk(void){ gp = malloc(8); }
__attribute__((noinline)) void rel(void){ free(gp); }
__attribute__((noinline)) void use(void){ consume(gp); }
int main(void){ mk(); rel(); use(); return 0; }
