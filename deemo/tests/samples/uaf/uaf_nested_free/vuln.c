#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-13: 嵌套结构释放 — 外层free后内层指针仍可被访问 */
typedef struct { int count; char **items; } Container;
int main(void) {
    Container *c = (Container *)malloc(sizeof(Container));
    c->count = 3;
    c->items = (char **)malloc(3 * sizeof(char *));
    for (int i = 0; i < 3; i++) {
        c->items[i] = (char *)malloc(16);
        sprintf(c->items[i], "item_%d", i);
    }
    /* 先释放items, 再释放container — 但顺序错 */
    free(c);  /* 外层先释放了! */
    for (int i = 0; i < 3; i++)
        printf("%s\n", c->items[i]);  /* VULNERABLE: c已释放 */
    for (int i = 0; i < 3; i++) free(c->items[i]);
    free(c->items);
    return 0;
}
