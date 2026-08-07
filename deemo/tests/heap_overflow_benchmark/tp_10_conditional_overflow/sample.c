/*
 * TP-10: Conditional Overflow on Branch Path (CWE-122)
 *
 * malloc(N) → 只有特定条件下溢出 (路径敏感判定)
 * 一条路径写入安全, 另一条路径溢出 → LPVRA应保留(UNCERTAIN/OVERFLOW)
 *
 * 真实漏洞类比: CVE-2020-16040 (Chrome V8 条件路径溢出)
 */
#include <stdlib.h>
#include <string.h>

int process_with_flag(int sz, int flag) {
    char *buf = (char *)malloc(sz);   /* sz = 64 */
    if (!buf) return -1;

    if (flag) {
        /* 安全路径: 写入在当前边界内 */
        buf[32] = 'S';
    } else {
        /* 溢出路径: 写入超出边界 */
        buf[128] = 'O';  /* sz=64, offset=128 → 确定性溢出 */
    }

    free(buf);
    return 0;
}

int main(void) {
    return process_with_flag(64, 0);
}
