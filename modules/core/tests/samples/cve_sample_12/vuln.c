/* 递归结构导致的堆溢出 — 测试路径深度限制 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node { char *data; struct node *next; } node_t;

node_t *build_chain(int depth, char *payload, size_t plen) {
    if (depth <= 0) return NULL;
    node_t *n = (node_t *)malloc(sizeof(node_t));
    n->data = (char *)malloc(32);
    /* 漏洞: plen 可达 256, 分配仅 32 */
    memcpy(n->data, payload, plen < 256 ? plen : 256);
    n->next = build_chain(depth - 1, payload, plen);
    return n;
}

int main(void) {
    char p[256]; memset(p, 'R', sizeof(p));
    node_t *head = build_chain(5, p, 200);
    printf("chain built\n");
    return 0;
}
