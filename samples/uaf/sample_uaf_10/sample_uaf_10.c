/*
 * sample_uaf_10 — Struct member pointer UAF.
 *
 * 结构体包含指针成员, free结构体后通过成员指针访问.
 * 部分UAF涉及对象的成员指针, 非直接释放.
 *
 * TARPS预期: DEF_TP — 结构体成员UAF
 * 编译: gcc -o sample_uaf_10 sample_uaf_10.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int size;
    char *payload;
    char *backup;
} Container;

int main(void) {
    Container *c = (Container *)malloc(sizeof(Container));
    if (!c) return 1;

    c->size = 128;
    c->payload = (char *)malloc(c->size);
    c->backup = (char *)malloc(c->size);
    if (!c->payload || !c->backup) return 1;

    strcpy(c->payload, "sensitive_payload");

    /* 释放了Container, 但成员指针未先释放 */
    free(c);

    /* UAF: c已被释放, 但其成员指针也变成了悬垂指针 */
    /* c->payload现指向已被释放的内存区域 */
    strcpy(c->backup, c->payload);  /* UAF: 读取已释放的payload */

    printf("leaked\n");
    return 0;
}
