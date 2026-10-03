/* INTOVF-006: 有符号/无符号转换溢出——符号差异导致宽度扩展/截断
 * 场景: int32传参→size_t扩展→负值变为极大无符号值→malloc(极大值)
 *   若user_cnt=-1 → (size_t)-1=0xFFFFFFFFFFFFFFFF → malloc(≈16EB)
 *   或 struct_len=(uint16_t)int_val; 若int_val=-1→截断为65535→calloc(65535,1)
 * 检测器能力: 有符号→无符号转换+传递给alloc→CONFIRMED/LIKELY
 * 预期: IntOverflowDeepAnalyzer检测到signed→unsigned传递, risk>=LIKELY
 *
 * 参考: CWE-681 (整数→无符号转换), CVE-2019-11477 (TCP SACK panic)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* BUG: 有符号int→无符号size_t——负值变为极大值 */
void *alloc_n_items(int count, size_t item_size) {
    /* count=-1 → (size_t)-1 → 0xFFFF... → malloc(极大值) → 必然失败 */
    /* 但若count是精确控制的负值, (size_t)count*item_size可能恰好为小值 */
    size_t total = (size_t)count * item_size;
    return malloc(total);
}

/* BUG: 变体——int截断为uint16_t后用于分配 */
typedef struct {
    uint16_t count;
    uint8_t flags;
    char data[];
} DynamicArray;

DynamicArray *create_array(int num_items) {
    /* num_items=65536 → (uint16_t)截断为0 → calloc(0+sizeof(hdr))
     * 但调用者认为分配了65536个元素 → 越界访问 */
    uint16_t cnt = (uint16_t)num_items;
    size_t alloc_sz = sizeof(DynamicArray) + cnt * 4;
    DynamicArray *arr = (DynamicArray *)malloc(alloc_sz);
    if (!arr) return NULL;
    arr->count = cnt;
    /* 若num_items>65535, 调用者会访问arr->data[65535+]——越界 */
    return arr;
}

/* BUG: 变体2——int8_t→uint32_t符号扩展问题 */
uint32_t offset_from_int8(int8_t rel_offset) {
    /* rel_offset=-128 → 符号扩展到int → (uint32_t)-128 → 0xFFFFFF80 */
    return (uint32_t)rel_offset;
}

/* 安全对照: 检查符号 */
void *alloc_n_items_safe(int count, size_t item_size) {
    if (count < 0) return NULL;
    size_t total = (size_t)count * item_size;
    return malloc(total);
}

int main(void) {
    void *p1 = alloc_n_items(10, 32);  /* 10*32=320——安全 */
    if (p1) free(p1);

    DynamicArray *arr = create_array(100);  /* 100≤65535——安全 */
    if (arr) free(arr);

    printf("signed/unsigned conversion test complete\n");
    return 0;
}
