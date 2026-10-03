/*
 * TP-08: realloc Shrink Then Old-Size Write (CWE-122)
 *
 * realloc缩小缓冲区后仍按旧大小写入 → 溢出到已被回收的空间
 * 需要知道realloc新分配大小 ≠ 旧大小
 *
 * 真实漏洞类比: CVE-2019-12815 (ProFTPD mod_copy realloc误用)
 */
#include <stdlib.h>
#include <string.h>

int shrink_and_write(void) {
    char *buf = (char *)malloc(4096);
    if (!buf) return -1;

    /* realloc缩小到64B */
    buf = (char *)realloc(buf, 64);
    if (!buf) return -1;

    /* 仍按旧大小写入 → 4096-64=4032字节溢出 */
    memset(buf, 0x45, 4096);

    free(buf);
    return 0;
}

int main(void) {
    return shrink_and_write();
}
