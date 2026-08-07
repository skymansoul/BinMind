/*
 * sample_uaf_01 — 基础 Use-After-Free.
 *
 * 漏洞: free(p) 后通过 *p 写入, 典型的 UAF 模式.
 * CWE-416: Use After Free.
 *
 * TARPS预期: DEF_TP — 五阶段全部确认危险
 * 编译: gcc -o sample_uaf_01 sample_uaf_01.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char data[32];
} Record;

int main(void) {
    Record *p = (Record *)malloc(sizeof(Record));
    if (!p) return 1;
    p->id = 42;
    strcpy(p->data, "sensitive");

    free(p);

    /* UAF: 释放后写入 */
    p->id = 0;
    strcpy(p->data, "overwrite");

    printf("done\n");
    return 0;
}
