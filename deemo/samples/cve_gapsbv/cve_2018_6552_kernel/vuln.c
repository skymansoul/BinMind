/*
 * CVE-2018-6552 — Linux kernel: relayfs 堆溢出 (CWE-122)
 *
 * Linux kernel 4.16.1 之前: kernel/relay.c 中 relay_open() 的
 * subbuf_size 参数未经过上限检查, 攻击者通过设置超大 subbuf 大小
 * 导致 vmalloc 分配不足, 后续 relay_write 在子缓冲区边界处溢出.
 *
 * 模式: vmalloc(n * m) 的 n 或 m 是用户控制值, 乘积溢出回绕.
 *
 * CVSS: 7.8 (High), CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟 relay_open + relay_write 模式 */
int relay_write_subbuf(size_t subbuf_sz, unsigned int n_subbufs,
                        const char *data, size_t data_len) {
    /*
     * [VULN] subbuf_sz * n_subbufs 可能乘积溢出
     * 如果 subbuf_sz = 0x40000000 (1GB), n_subbufs = 8
     * → alloc_sz = 0 (32位回绕) 或 2GB (64位不足)
     */
    size_t alloc_sz;
    if (__builtin_mul_overflow(subbuf_sz, n_subbufs, &alloc_sz)) {
        return -1; /* 编译器内建检查 — 但 kernel 旧版没用 */
    }
    /* 如果 mul_overflow 不可用, 检查可能被绕过 */

    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return -2;

    /* [VULN] subbuf_sz 是用户定义的值, data_len 可能 > subbuf_sz
     * 每个子缓冲区的写入使用 subbuf_sz 作为边界, 但数据长度更大
     */
    for (unsigned int i = 0; i < n_subbufs; i++) {
        size_t offset = i * subbuf_sz;
        size_t copy_sz = data_len; /* ← 缺陷: 应为 min(data_len, subbuf_sz) */

        if (offset + copy_sz > alloc_sz) {
            break; /* 仅在所有子缓冲区写完后才检查 */
        }
        memcpy(buf + offset, data + (i * subbuf_sz), copy_sz);
    }

    free(buf);
    return 0;
}

int main(void) {
    char data[8192];
    memset(data, 'R', sizeof(data));

    /* 请求 256 个 64B 子缓冲区, 但每次写入 256B → 溢出 */
    return relay_write_subbuf(64, 256, data, 256);
}
