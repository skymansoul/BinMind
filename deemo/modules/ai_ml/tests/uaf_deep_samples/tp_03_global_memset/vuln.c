#include <stdlib.h>
#include <string.h>
typedef struct { int tag; char buf[64]; } obj_t;
obj_t *gm;
__attribute__((noinline)) void mk(void){ gm = malloc(sizeof(obj_t)); }
__attribute__((noinline)) void rel(void){ free(gm); }
__attribute__((noinline)) void clr(void){ if (gm) memset(gm, 0, sizeof(obj_t)); }
int main(void){ mk(); rel(); clr(); return 0; }
