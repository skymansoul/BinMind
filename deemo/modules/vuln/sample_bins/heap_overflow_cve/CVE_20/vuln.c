/* CVE-2019-11043 (堆溢出) — 多段写入累加越界
 * 漏洞类型: 堆溢出 (同址多次memcpy累加)
 * 触发条件: malloc(32), 循环3次 memcpy(buf+off, src, 16)
 * 根因: 3×16=48 > 32, 累加越界
 * 有效原因: 测试循环累加写入检测 (trip×stride vs alloc)
 */
#include <stdlib.h>
#include <string.h>

void segmented_write(char *src) {
    char *buf = (char *)malloc(32);
    if (!buf) return;
    size_t off = 0;
    for (int i = 0; i < 3; i++) {   /* 3次 */
        memcpy(buf + off, src, 16); /* 16×3=48 > 32 */
        off += 16;
    }
    free(buf);
}

int main() {
    char data[64] = "ABCDEFGHIJKLMNOP";
    segmented_write(data);
    return 0;
}
