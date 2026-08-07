/*
 * TP-01: Classic Linear Heap Overflow (CWE-122)
 *
 * malloc(64) → 写入 offset=96 处 4 字节 → 确定性溢出
 * LPVRA应判定: OVERFLOW (write_end=100 > 任何chunk边界)
 *
 * 真实漏洞类比: CVE-2014-1767 (AFD.sys pool overflow)
 */
#include <stdlib.h>
#include <string.h>

int process_data(int trigger) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;

    if (trigger) {
        buf[96] = 'X';  /* offset=96, write=1, total=97 */
    }

    free(buf);
    return 0;
}

int main(void) {
    return process_data(1);
}
