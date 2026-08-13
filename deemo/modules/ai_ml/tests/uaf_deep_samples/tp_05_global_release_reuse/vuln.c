#include <stdlib.h>
#include <string.h>
char *gc; int gclen;
__attribute__((noinline)) void fill(int n){ gc = malloc(n); gclen = n; }
__attribute__((noinline)) void release(void){ free(gc); }
__attribute__((noinline)) int check(void){ if (gc) return gc[0]; return 0; }
int main(void){ fill(8); release(); check(); return 0; }
