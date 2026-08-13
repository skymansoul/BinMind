#include <stdlib.h>
typedef struct { int refs; char data[8]; } item_t;
item_t *gi;
__attribute__((noinline)) void mk(void){ gi = malloc(sizeof(item_t)); }
__attribute__((noinline)) void rel(void){ free(gi); }
__attribute__((noinline)) int rd(void){ if (gi) return gi->refs; return -1; }
int main(void){ mk(); rel(); rd(); return 0; }
