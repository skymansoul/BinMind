/*
 * sample_uaf_07 — Loop-based UAF.
 *
 * 循环内malloc/free, 但free后循环继续使用指针.
 * 典型的迭代处理中的UAF模式.
 *
 * TARPS预期: DEF_TP — free后循环内持续使用
 * 编译: gcc -o sample_uaf_07 sample_uaf_07.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    int id;
    char data[64];
} Node;

int main(void) {
    Node *nodes[3] = {NULL, NULL, NULL};

    for (int i = 0; i < 3; i++) {
        nodes[i] = (Node *)malloc(sizeof(Node));
        if (!nodes[i]) return 1;
        nodes[i]->id = i + 1;
        snprintf(nodes[i]->data, 64, "node_%d", i);
    }

    /* 释放中间节点 */
    free(nodes[1]);

    /* UAF: 循环遍历时仍使用已释放的节点 */
    for (int i = 0; i < 3; i++) {
        if (nodes[i] != NULL) {
            printf("node[%d]: id=%d\n", i, nodes[i]->id);
        }
    }

    /* cleanup remaining */
    free(nodes[0]);
    free(nodes[2]);
    return 0;
}
