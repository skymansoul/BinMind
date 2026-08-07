/* CVE-2022-0995 (Linux watch_queue) 堆溢出复现 — watch_queue_set_size 中
   OOB 写: 分配的页数经位运算后被覆盖, 写入超出缓冲. 简化: malloc(64)
   后按外部输入的 pages 常量 512 字节写入 (内部越界写). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf;
    unsigned int pages = 8; /* 用户可控制 */

    buf = (char *)malloc(64);
    if (!buf) {
        return 1;
    }
    memset(buf, 0, pages * 64);
    free(buf);
    return 0;
}
