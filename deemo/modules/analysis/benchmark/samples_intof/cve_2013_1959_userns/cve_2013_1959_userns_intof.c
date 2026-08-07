/**
 * CVE-2013-1959 — truncation downcast: uid_t (u32) truncated from u64
 * 模式: downcast
 *
 * 对静态分析的挑战:
 *   1. 溢出算术指令 (imul/shl/add) 的结果追踪
 *   2. 跨寄存器/栈槽的标记传播
 *   3. 编译器优化 (O2/Os) 后的模式识别
 *   4. 宽度转换 (32→64, 16→32) 的精确追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// downcast: u64->u32 truncation to uid_t
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2013_1959_userns_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t kuid = (uint64_t)count * 0x10000001ULL;  /* large factor */
    uint32_t uid = (uint32_t)kuid;  /* truncation! */
    int ngroups = (int)uid;  /* truncated value: small when count*mult wraps to <2^31 */
    if (ngroups > 0 && ngroups < 65536) {  /* bypassed */
      char *buf = (char *)malloc(ngroups * 8 + 1);
      if (!buf) return;
      memset(buf, 0, ngroups * 8 + 1);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2013_1959_userns: done\n");
}

__attribute__((noinline))
void v_2013_1959_userns_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t kuid = (uint64_t)count * 0x10000001ULL;
    if (kuid < (uint64_t)count) {  /* wrapped in 64-bit? should not happen */
      printf("overflow rejected\n");
      return;
    }
    if (kuid > (UINT32_MAX / 16)) {
      printf("overflow rejected\n");
      return;
    }
    uint32_t uid = (uint32_t)kuid;
    int ngroups = (int)uid;
    char *buf = (char *)malloc(ngroups * 8 + 1);
    if (!buf) return;
    memset(buf, 0, ngroups * 8 + 1);
    free(buf);
    printf("v_2013_1959_userns: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2013_1959_userns_vuln(count);
    v_2013_1959_userns_safe(count);
    return 0;
}
