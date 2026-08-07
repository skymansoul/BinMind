/* heap_overflow_06 — 结构体字段溢出 (struct field overflow)
 *
 * malloc(sizeof(struct)) 后对结构体中的数组成员越界写入.
 * 常发生于: sizeof 计算遗漏嵌套结构体或弹性数组成员的大小.
 * 测试检测器对结构体大小和字段边界的关系推导.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct record {
    int id;
    char name[32];
    int age;
    /* 弹性数组成员在此之后 — 此处用额外的固定数组 */
    char data[64];
};

int main(void) {
    /* BUG: 分配 sizeof(struct record) = 4+32+4+64 = 104,
     *       但写入时给 data 字段写了 128 bytes,
     *       因为实际 data 应该是弹性数组需要额外分配 */
    struct record *rec = (struct record *)malloc(sizeof(struct record));
    if (!rec) return 1;

    rec->id = 1;
    strcpy(rec->name, "test_user");
    rec->age = 25;

    /* BUG: data 字段只有 64 bytes, 但写入 128 bytes */
    memset(rec->data, 'D', 128);

    printf("record: id=%d name=%s age=%d data_tail=%c\n",
           rec->id, rec->name, rec->age, rec->data[127]);
    free(rec);
    return 0;
}
