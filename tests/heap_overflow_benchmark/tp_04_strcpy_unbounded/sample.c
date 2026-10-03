/*
 * TP-04: strcpy Unbounded Copy to Heap (CWE-120)
 *
 * malloc(16) → strcpy无界拷贝 → 源串远大于16 → 堆溢出
 * 经典缓冲区溢出: strcpy/dest大小不匹配
 *
 * 真实漏洞类比: CVE-2016-10158 (PHP exif_thumbnail_extract)
 */
#include <stdlib.h>
#include <string.h>

int copy_name(const char *name) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;

    strcpy(buf, name);  /* name可能>>16字节 → 无界写入溢出 */

    free(buf);
    return 0;
}

int main(void) {
    char long_name[256];
    memset(long_name, 'B', 255);
    long_name[255] = '\0';
    return copy_name(long_name);
}
