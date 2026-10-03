/* CVE-2021-3712 — realloc后堆溢出
 * 漏洞类型: 堆溢出 (realloc缩小后用旧大小写入)
 * 触发条件: ptr=malloc(256), ptr=realloc(ptr,64), memcpy(ptr,src,256)
 * 根因: realloc后大小更新但写入使用旧大小
 * 有效原因: 测试realloc场景的尺寸追踪
 */
#include <stdlib.h>
#include <string.h>

void realloc_overflow(char *src) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    buf = (char *)realloc(buf, 64);  /* 缩小到64 */
    if (!buf) return;
    memcpy(buf, src, 256);           /* 用旧大小256写入: 溢出 */
    free(buf);
}

int main() {
    char data[512] = "test";
    realloc_overflow(data);
    return 0;
}
