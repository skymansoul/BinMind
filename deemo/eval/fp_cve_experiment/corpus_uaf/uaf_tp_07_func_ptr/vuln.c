/* UAF-TP-07: 函数指针表释放后调用. */
#include <stdlib.h>
#include <stdio.h>

typedef void (*handler_t)(void);
void h1(void) { printf("h1\n"); }

int main(void) {
    handler_t *tab = (handler_t *)malloc(2 * sizeof(handler_t));
    if (!tab) return 1;
    tab[0] = h1;
    free(tab);
    tab[0]();
    return 0;
}
