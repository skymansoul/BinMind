/* NEG-005 — sizeof 模式, malloc 大小由 sizeof 推导, 写入量匹配 → 安全 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define N_ITEMS 100

typedef struct { int id; double val; char label[16]; } item_t;

void sizeof_safe_copy(const item_t *src) {
    item_t *buf = malloc(N_ITEMS * sizeof(item_t));
    if (!buf) return;
    memcpy(buf, src, N_ITEMS * sizeof(item_t));  /* 完全匹配 → 安全 */
    printf("sizeof safe: %zu bytes\n", N_ITEMS * sizeof(item_t));
    free(buf);
}

int main(int c, char **v) {
    item_t items[N_ITEMS];
    memset(items, 0, sizeof(items));
    sizeof_safe_copy(items);
    return 0;
}
