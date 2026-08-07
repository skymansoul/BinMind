/*
 * TP-06: Loop with Dynamic Bound Exceeding Alloc (CWE-122)
 *
 * malloc(sz) → for i < sz + 10 → 循环上界超过分配大小
 * 需要值域分析检测: 写入上界(hi_offset) > 分配下界(lo_size)
 *
 * 真实漏洞类比: CVE-2020-10713 (GRUB2 BootHole缓冲区溢出)
 */
#include <stdlib.h>
#include <string.h>

int fill_buffer(int sz) {
    char *buf = (char *)malloc(sz);
    if (!buf) return -1;

    /* 写入上界 = sz + 10 > sz → 至少溢出10字节 */
    for (int i = 0; i < sz + 10; i++) {
        buf[i] = 0x44;
    }

    free(buf);
    return 0;
}

int main(void) {
    return fill_buffer(4096);
}
