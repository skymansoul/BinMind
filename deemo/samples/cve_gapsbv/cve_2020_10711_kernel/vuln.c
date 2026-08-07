/*
 * CVE-2017-16995 — Linux kernel: eBPF 整数溢出→堆越界 (CWE-190→CWE-122)
 *
 * Linux kernel 4.14.8 ~ 4.14.11: kernel/bpf/verifier.c 中
 * check_alu_op() 的 BPF_ADD 处理存在整数溢出未检测的问题.
 * 攻击者构造的 eBPF 程序可让 verifier 认为一个指针加上可控偏移后
 * 仍在分配的映射值内, 但实际 32位加法溢出导致指针指向映射外.
 *
 * 关键代码: `dst_reg->var_off = tnum_add(dst_reg->var_off, tnum_const(imm))`
 * 未处理 32位回绕.
 *
 * CVSS: 7.8 (High), CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAP_VALUE_SIZE 256

/*
 * 模拟 BPF verifier + JIT 的双重人格:
 *   Verifier: 在抽象域中检查 (tnum/var_off)
 *   JIT: 生成实际 x86-64 指令
 *
 * 当 verifier 跟踪的是 32位有符号值域, 而 JIT 使用 64位指令时,
 * 32位回绕的条件在 64位下不成立 → verifier 认为安全, 实际溢出.
 */
int bpf_prog_load(uint32_t r1_val, uint32_t r2_val,
                  const uint8_t *data) {
    uint8_t *map_val = (uint8_t *)malloc(MAP_VALUE_SIZE);
    if (!map_val) return -1;

    /*
     * verifier 追踪:
     *   r1 = 0x7FFFFFFF  (最大正 int32)
     *   r2 = 0x00000040  (64)
     *   r3 = r1 + r2      → verifier: r3 = 0x8000003F (int32: -2147483585)
     *
     * verifier 在 32位域检查:
     *   0x8000003F (unsigned) → 大于 MAP_VALUE_SIZE → 拒绝? NO!
     *
     * [VULN] verifier 用 int32 比较: r3 < MAP_VALUE_SIZE (int32)
     *   0x8000003F (unsigned 2147483711) ≥ 256 → 应该拒绝
     *   但 -2147483585 (signed) < 256 → 允许!
     *
     * JIT 生成: `add eax, edx` (32位 → 零扩展到 64位)
     *   结果: rax = 0x000000008000003F (2147483711) → 巨大正偏移!
     */

    int32_t idx = (int32_t)(r1_val + r2_val);

    /* verifier 的有符号检查 — 对 0x8000003F 通过! */
    if (idx < 0) {
        free(map_val);
        return -1; /* 只拒绝负数 — 但 0x8000003F 不被认为是负 */
    }
    if (idx >= MAP_VALUE_SIZE) {
        free(map_val);
        return -1; /* [VULN] 在 int32 域: -2147483585 < 256 → 通过! */
    }

    /* JIT: (uint32_t)(r1+r2) = 0x8000003F = 2147483711 */
    uint32_t actual_offset = r1_val + r2_val; /* 零扩展 → 巨大值 */
    memcpy(map_val + actual_offset, data, 32); /* ← 越界写 */

    free(map_val);
    return 0;
}

int main(void) {
    uint8_t payload[32];
    memset(payload, 0xE9, sizeof(payload));

    /* r1 = INT32_MAX-63, r2 = 128 → 32位和 = 0x8000003F
     * verifier 认为 -2147483585 < 256 ✓, 但实际偏移 = 2147483711
     */
    return bpf_prog_load(0x7FFFFFC0, 0x7F, payload);
}
