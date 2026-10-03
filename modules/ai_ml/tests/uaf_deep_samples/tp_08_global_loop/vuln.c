#include <stdlib.h>
char *gl;
__attribute__((noinline)) void mk(void){ gl = malloc(64); }
__attribute__((noinline)) void rel(void){ free(gl); }
__attribute__((noinline)) int sum(void){ int s = 0; if (gl) for (int i = 0; i < 64; i++) s += gl[i]; return s; }
int main(void){ mk(); rel(); sum(); return 0; }
