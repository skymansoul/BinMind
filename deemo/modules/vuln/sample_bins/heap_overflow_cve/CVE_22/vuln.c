/* CVE-2016-1000212 (堆溢出) — 小请求下分配器 usable 边界误判
 * 漏洞类型: 堆溢出 (请求16字节, 写入30字节)
 * 触发条件: malloc(16), memcpy(buf, src, 30)
 * 根因: 请求16, aligned_hi=32, 真实 usable(16)=24, 写入30>24 溢出
 * 有效原因: 测试 AWSC padding-safe 判定的 usable 计算:
 *   修复前 usable(aligned_hi=32)=40, 30≤40 误判安全 (漏报);
 *   修复后 usable(请求下界17)=24, 30>24 正确报溢出
 */
#include <stdlib.h>
#include <string.h>

void small_alloc_overflow(char *src) {
    char *buf = (char *)malloc(16);
    if (!buf) return;
    memcpy(buf, src, 30);   /* 30 > usable(16)=24, 溢出 */
    free(buf);
}

int main() {
    char data[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    small_alloc_overflow(data);
    return 0;
}
