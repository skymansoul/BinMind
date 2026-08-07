/* CVE-2023-28456 — 堆溢出, 对齐后看似安全实则溢出
 * 漏洞类型: 堆溢出 (分配器对齐掩盖的实际溢出)
 * 触发条件: malloc(62), memcpy(buf, data, 80)
 * 根因: 62对齐到64(glibc), 但写入80仍超过对齐后大小
 * 有效原因: 测试分配器感知模型是否正确判断溢出
 */
#include <stdlib.h>
#include <string.h>

void aligned_alloc_overflow(char *data) {
    char *buf = (char *)malloc(62);   /* glibc对齐到64, 可用48 */
    if (!buf) return;
    memcpy(buf, data, 80);            /* 80 > 64: 确定溢出 */
    free(buf);
}

int main() {
    char data[256];
    aligned_alloc_overflow(data);
    return 0;
}
