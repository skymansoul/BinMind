/* UAF-TP-11: 全局指针 g 释放后 use_global 解引用. */
#include <stdlib.h>
#include <stdio.h>

static char *g;
void init_global(void) { g = (char *)malloc(16); }
void free_global(void) { free(g); }
void use_global(void) { g[0] = 'G'; }

int main(void) {
    init_global();
    if (!g) return 1;
    free_global();
    use_global();
    printf("%c\n", g[0]);
    return 0;
}
