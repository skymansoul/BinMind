/*
 * CVE-2022-23222 — Linux kernel: eBPF verifier 绕过→任意读写 (CWE-787)
 *
 * Linux kernel 5.16.1 之前: kernel/bpf/verifier.c 中
 * 对 32位有符号边界检查的处理不正确, 攻击者构造的 eBPF 程序
 * 可欺骗 verifier 以为某个寄存器值在安全范围内, 但实际运行时
 * 可以取任意值, 导致越界读写内核堆内存.
 *
 * 模式: verifier 检查使用 int32, 但实际执行使用 int64/指针
 *
 * CVSS: 7.8 (High), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟 eBPF map 值读写 */
#define MAP_VALUE_SIZE 64

int bpf_map_update(int32_t user_key, int32_t user_idx,
                   const uint8_t *user_data, uint32_t data_len) {
    /*
     * [VULN] verifier 在 int32 域中检查: user_idx 在 [0, 63]
     * 但 JIT 编译后使用 64位寄存器, user_idx 可以是一个
     * 看起来为负的 32位值但在 64位下为正的巨大值
     */
    uint8_t *map_value = (uint8_t *)malloc(MAP_VALUE_SIZE);
    if (!map_value) return -1;
    memset(map_value, 0, MAP_VALUE_SIZE);

    /* verifier 检查: 0 <= user_idx <= 63 (int32 域) */
    /* [VULN] 若 user_idx = (int32_t)0xFFFFFF00 (-256),
     * 检查通过 (int32: -256 < 63),
     * 但 JIT 代码用 64位偏移: *(u64*)(map_value + (u32)user_idx)
     * → 越界写 @ map_value + 0xFFFFFF00
     */
    int32_t idx = user_idx; /* 保留有符号语义 */

    if (idx < 0 || idx >= MAP_VALUE_SIZE) {
        /* verifier 认为对 -256 会走这里... */
        free(map_value);
        return -1;
    }

    /* [VULN] ...但实际上 compiler 将 idx 零扩展为 size_t,
     * (size_t)(int32_t)(-256) = 0xFFFFFF00 → 巨大正偏移
     */
    uint32_t offset = (uint32_t)idx; /* -256 → 0xFFFFFF00 */
    if (offset + data_len > MAP_VALUE_SIZE) {
        /* offset = 0xFFFFFF00, 此检查通过 (因为回绕) */
        free(map_value);
        return -1;
    }

    memcpy(map_value + offset, user_data, data_len); /* ← 越界写 */
    free(map_value);
    return 0;
}

int main(void) {
    uint8_t evil_data[32];
    memset(evil_data, 0x42, sizeof(evil_data));

    /* user_idx = -256 (0xFFFFFF00), 在 int32 域 = -256 < 64 ✓
     * 但实际偏移 = 0xFFFFFF00 → 灾难
     */
    return bpf_map_update(1, -256, evil_data, sizeof(evil_data));
}
