/*
 * TP-09: Multi-Alloc Adjacent Chunk Overflow (CWE-122)
 *
 * buf1=malloc(32), buf2=malloc(32) → 写入buf1越界覆盖buf2
 * 需要跨chunk的别名跟踪才能关联写入目标与溢出影响
 *
 * 真实漏洞类比: CVE-2017-5638 (Apache Struts2 Jakarta Multipart)
 */
#include <stdlib.h>
#include <string.h>

int multi_buffer_overflow(void) {
    char *buf1 = (char *)malloc(32);
    char *buf2 = (char *)malloc(32);

    if (!buf1 || !buf2) {
        free(buf1); free(buf2);
        return -1;
    }

    strcpy(buf2, "safe_data");

    /* 向buf1写入64字节, 溢出覆盖相邻的buf2 chunk */
    memset(buf1, 0x46, 64);

    free(buf1);
    free(buf2);
    return 0;
}

int main(void) {
    return multi_buffer_overflow();
}
