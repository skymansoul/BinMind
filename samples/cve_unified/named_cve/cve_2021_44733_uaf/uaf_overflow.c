/*
 * CVE-2021-44733 — Linux kernel io_uring UAF (简化复现)
 * 虽然主要是 UAF, 但攻击链中常伴随堆溢出或写越界.
 *
 * 漏洞机制:
 *   io_uring 的固定缓冲区注册功能 (IORING_REGISTER_BUFFERS) 中,
 *   io_sqe_buffers_register() 分配固定缓冲区数组,
 *   但在特定错误路径中释放后未清理指针, 导致 UAF.
 *   攻击者通过 UAF 可获得对已释放内存的读写控制,
 *   进一步通过堆风水实现任意写 → 提权.
 *
 * 本文件简化: UAF 如何演变为写越界 —
 *   已释放的指针仍可被引用, 且引用时的大小可能超过
 *   重新分配时的大小, 导致通过 UAF 实现堆溢出.
 *
 * 影响: 本地提权 (任何非特权用户可创建 io_uring 实例).
 * 修复: 清理固定缓冲区释放后的悬垂指针.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* 模拟 io_uring 固定缓冲区描述符 */
typedef struct {
    void   *buf;
    size_t  len;       /* 原始分配长度 */
    int     registered; /* 是否已注册 */
} FixedBuf;

/*
 * 漏洞函数: UAF 导致后续写入溢出
 * 阶段1: 分配并注册缓冲区, 然后释放但未清空指针
 * 阶段2: 另一分配重用此内存 (变小)
 * 阶段3: 通过悬垂指针向旧大小写入
 */
void io_uring_uaf_to_overflow(void) {
    FixedBuf *reg = (FixedBuf *)calloc(1, sizeof(FixedBuf));
    if (!reg) return;

    /* 阶段1: 注册大缓冲区 */
    reg->buf = malloc(4096);
    reg->len = 4096;
    reg->registered = 1;
    printf("  [1] Registered buffer: %p, len=%zu\n", reg->buf, reg->len);

    /* 漏洞: 在某些错误路径中释放但不清除指针和 registered 标志
     * 模拟: free(reg->buf); reg->registered = 0; // 但 reg->buf 未置 NULL! */
    void *dangling = reg->buf;
    free(reg->buf);
    reg->registered = 0;
    /* reg->buf 仍指向已释放的内存 ← 悬垂指针! */

    printf("  [2] Freed but dangling ptr: %p\n", dangling);

    /* 阶段2: 其他分配重用此内存, 分配更小的对象 */
    uint8_t *small_obj = (uint8_t *)malloc(64);
    printf("  [3] Reallocated smaller: %p, size=64\n", (void *)small_obj);
    memset(small_obj, 0xBB, 64);

    /* 阶段3: 通过悬垂指针向超出原始分配大小的量写入 —
     *        原始分配4096字节, 写入8192字节溢出 */
    if (dangling) {
        printf("  [4] Writing 8192 bytes through dangling ptr -> OVERFLOW!\n");
        memset(dangling, 0x41, 8192); /* 写入远超原始4096字节分配! */
    }

    free(small_obj);
    free(reg);
}

int main(void) {
    printf("[*] io_uring UAF-to-overflow test (CVE-2021-44733 pattern)\n");
    io_uring_uaf_to_overflow();
    printf("[!] UAF demonstrated\n");
    return 0;
}
