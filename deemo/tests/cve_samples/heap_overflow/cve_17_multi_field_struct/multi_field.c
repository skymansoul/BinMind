/*
 * CVE-17: 多字段结构体 — stride-based FP reduction test
 *
 * 场景: sizeof(LargeStruct)=96, 多个字段逐个写入, offset 逐步递增.
 *       按 strided interval: 每次写入 offset 递增 sizeof(field),
 *       最终 offset=88 < sizeof(Struct)=96 → 安全.
 *
 * 但若浅层分析只看最后一条 store at offset 88 + 8B → end=96, 刚好边界.
 * stride 分析可证明: 所有访问对齐到 4B stride, 且总范围在 [0, 96) 内.
 *
 * 预期: 不是溢出 — strided interval 验证应确认为安全
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;           // offset 0, size 4
    int version;      // offset 4, size 4
    char name[32];    // offset 8, size 32
    char path[48];    // offset 40, size 48 — total=88
    long checksum;    // offset 88, size 8 — total=96
} LargeStruct;

int main(void) {
    LargeStruct *s = (LargeStruct *)malloc(sizeof(LargeStruct));
    if (!s) return 1;

    s->id = 1;
    s->version = 2;
    strcpy(s->name, "test");
    strcpy(s->path, "/tmp/test");
    s->checksum = 0xDEADBEEFDEADBEEFL;

    printf("struct size=%zu, checksum=%lx\n",
           sizeof(LargeStruct), s->checksum);
    free(s);
    return 0;
}
