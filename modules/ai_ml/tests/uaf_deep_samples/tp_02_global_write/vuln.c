#include <stdlib.h>
char *gw;
__attribute__((noinline)) void set(void){ gw = malloc(32); }
__attribute__((noinline)) void rel(void){ free(gw); }
__attribute__((noinline)) void use(void){ if (gw) { gw[0] = 'X'; gw[1] = 'Y'; } }
int main(void){ set(); rel(); use(); return 0; }
