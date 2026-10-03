#include <stdio.h>
#include <stdlib.h>
typedef void (*fn_t)(void);
void good() { printf("ok\n"); }
int main() { fn_t *slot = malloc(sizeof(fn_t));
*slot = good; free(slot); (*slot)(); return 0; }
