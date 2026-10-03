/* Integer overflow → heap overflow (CVE-2016-2208 类型).
 *
 * n * sizeof(elem) 回绕到小值, malloc 分配不足,
 * memcpy 按原始 n 写入 → 堆溢出.
 * Expected: TP (confidence ≥ 0.85)
 */
#include <stdlib.h>
#include <string.h>

typedef struct { char data[256]; } Elem;

int main() {
    unsigned int n = 0x01000001;  /* 16M+1, 乘积回绕 */
    size_t alloc_size = n * sizeof(Elem);
    /* alloc_size = 0x01000001 * 256 mod 2^32 = 256, 远小于 n*256 */
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    /* memcpy 期望写 n*sizeof(Elem) ≈ 256MB, 实际 alloc=256B → 溢出 */
    memset(buf, 0, (size_t)n * 256);
    free(buf);
    return 0;
}
