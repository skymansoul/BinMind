/* CVE-2021-22555 (netfilter xt_compat) 堆溢出复现 — 用户态表格复制时
   目标条目偏移计算错误, 导致 OOB 写. 简化: malloc(64) 后按动态偏移
   off 写入 0x40 字节, off 来自外部输入可接近分配上界. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t compute_offset(void) {
    /* 真实漏洞: 对齐后目标偏移越过条目数组末尾 */
    return 48;
}

int main(void) {
    char *buf;
    size_t off;

    buf = (char *)malloc(64);
    if (!buf) {
        return 1;
    }
    off = compute_offset();
    memset(buf + off, 0, 64);
    free(buf);
    return 0;
}
