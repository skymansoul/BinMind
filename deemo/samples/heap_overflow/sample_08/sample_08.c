/*
 * sample_08 — 嵌套结构体堆溢出.
 *
 * 漏洞: 结构体包含固定大小数组, malloc 分配结构体本身,
 * 但对数组的写入使用外部传入的 size → 可能溢出.
 *
 * CWE-122. 类似于 CVE-2014-0196 (Linux kernel pty 驱动) 的模式.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    int data_len;
    char name[32];
    char *payload;
} Record;

int main(void) {
    Record *rec = (Record *)malloc(sizeof(Record));
    if (!rec) return 1;

    /* payload 分配 64 字节 */
    rec->payload = (char *)malloc(64);
    rec->data_len = 256;  /* 错误: 应该是64 */

    /* 按 data_len(256) 写入 payload(64) → 溢出 192 字节 */
    memset(rec->payload, 'X', rec->data_len);

    printf("rec->id = %d\n", rec->id);
    free(rec->payload);
    free(rec);
    return 0;
}
