/*
 * CVE-04: strcpy 堆溢出
 *
 * 模式: malloc(N) → strcpy(buf, long_string) where strlen > N
 * 触发: 分配 16B, strcpy 写入 64B 的字符串 → 溢出 48B
 *
 * 对应真实 CVE: CVE-2016-10158 (PHP exif_thumbnail_extract)
 * 检测预期: strcpy 无边界检查 → 真阳性
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return 1;

    // 源字符串远超分配大小
    const char *payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    strcpy(buf, payload);

    printf("strcpy overflow: %s\n", buf);
    free(buf);
    return 0;
}
