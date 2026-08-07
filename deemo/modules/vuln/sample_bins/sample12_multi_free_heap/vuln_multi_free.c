/* sample12: 多次分配+释放场景中的堆溢出
 *
 * 漏洞类型: Heap overflow between multiple alloc/free
 * 触发条件: 第一次free后内存被回收, 新分配复用了旧内存块,
 *          但代码仍通过旧指针访问 → 堆溢出 (或UAF变种)
 * 测试价值: 多分配/释放交错场景, 测试指针追踪的准确性
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void multi_alloc_overflow(void) {
    char *a = (char *)malloc(64);
    char *b = (char *)malloc(128);
    memset(a, 'A', 64);
    memset(b, 'B', 128);

    free(a);  // a释放, 64字节块回收到fastbin
    // [VULN] c可能复用了a的内存位置
    char *c = (char *)malloc(64);

    // 若c == a (fastbin LIFO), 下面通过旧指针b+偏移写入可能
    // 意外写到c的区域 — 这不是直接的堆溢出, 而是混淆
    // 真正的漏洞: 若某路径使用a的size(64)去memcpy到c, 且实际数据>64
    memcpy(c, "SHORT", 5);  // safe
    // [VULN] 用旧的分配大小写新块 — 若新块实际可用大小不同
    memcpy(b, "OVERFLOW_DATA_OVERFLOW_DATA_OVERFLOW_DATA_OVERFLOW_DATA", 50);
    printf("b: %s\n", b);
    free(b);
    free(c);
}

int main(void) {
    multi_alloc_overflow();
    return 0;
}
