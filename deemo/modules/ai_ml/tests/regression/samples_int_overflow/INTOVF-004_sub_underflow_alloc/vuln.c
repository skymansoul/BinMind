/* INTOVF-004: sub下溢——减法结果越过0变为极大值导致分配不足
 * 场景: alloc_size = size - header; 若size < header → 下溢为巨大值
 *   若size=10, header=16 → 10-16=-6 → (size_t)-6=0xFFFFFFFA → malloc(≈4G)
 * 检测器能力: sub下溢→无符号环绕→传递给malloc→CONFIRMED/LIKELY
 * 预期: IntOverflowDeepAnalyzer检测到sub+alloc关联, risk>=LIKELY
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define MIN_HDR 16

/* BUG: sub下溢——若data_size < MIN_HDR, alloc_size变为极大值 */
void *alloc_with_gap(size_t data_size) {
    /* data_size=10 → 10-16 → 0xFFFFFFFA (32位下≈4G) */
    size_t alloc_size = data_size - MIN_HDR;
    /* 下溢后malloc(≈4G)必然失败, 但32位系统上可能截断为小值 */
    return malloc(alloc_size);
}

/* BUG: 变体——带额外偏移的sub下溢 */
char *create_buffer(size_t user_len) {
    /* 若user_len=0 → 0-1-8 → 下溢 */
    size_t total = user_len - 1 - 8;
    char *buf = (char *)malloc(total);
    if (!buf) return NULL;
    /* 若下溢使total变小而malloc成功, memset会越界 */
    memset(buf, 0, user_len);
    return buf;
}

/* 安全对照: 预先检查size >= header */
void *alloc_with_gap_safe(size_t data_size) {
    if (data_size < MIN_HDR) return NULL;
    size_t alloc_size = data_size - MIN_HDR;
    return malloc(alloc_size);
}

int main(void) {
    void *p1 = alloc_with_gap(128);  /* 128-16=112——安全 */
    if (p1) free(p1);

    void *p2 = alloc_with_gap(8);    /* 8-16→下溢——危险 */
    if (p2) free(p2);

    printf("sub underflow test complete\n");
    return 0;
}
