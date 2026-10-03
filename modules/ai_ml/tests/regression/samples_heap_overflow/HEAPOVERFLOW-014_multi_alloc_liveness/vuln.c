/* HEAPOVERFLOW-014: 多分配器混淆——测试L1配对+L2分配器模型
 * 函数内有3个不同大小的malloc，memcpy的dst来自第2个malloc
 * 最近malloc启发式会错误关联到第3个malloc(距离最近)
 * L1的寄存器liveness追踪应正确配对到第2个malloc
 */

#include <stdlib.h>
#include <string.h>

void multi_alloc_memcpy(void *input, int len) {
    /* alloc#1: 256字节——用于base buffer */
    char *base = (char *)malloc(256);

    /* alloc#2: 128字节——memcpy的真正目标 */
    char *work = (char *)malloc(128);

    /* alloc#3: 64字节——在memcpy之后分配(距离更近但无关) */
    char *meta = (char *)malloc(64);

    /* memcpy的目标是work(来自alloc#2)，
     * 但最近malloc是alloc#3(64字节)
     * 最近启发式: 64 < 96 → 误报溢出
     * L1 liveness追踪: rdi←work←rax(alloc#2) → 128 ≥ 96 → 正确判定安全 */
    if (work && input && len > 0 && len <= 96) {
        memcpy(work, input, len);
    }

    if (meta) {
        memcpy(meta, "metadata", 8);
    }

    free(base);
    free(work);
    free(meta);
}

int main() {
    char data[100];
    memset(data, 'A', sizeof(data));
    multi_alloc_memcpy(data, 96);
    return 0;
}
