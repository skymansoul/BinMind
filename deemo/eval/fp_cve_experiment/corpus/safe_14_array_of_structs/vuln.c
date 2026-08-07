/* 安全: 结构体数组 p[i] 逐元素写入, i<16 界内. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int id;
    int val;
} item;

int main(void) {
    item *p = (item *)malloc(16 * sizeof(item));
    if (!p) return 1;
    for (int i = 0; i < 16; i++) {
        p[i].id = i;
        p[i].val = i * 2;
    }
    printf("%d\n", p[15].val);
    free(p);
    return 0;
}
