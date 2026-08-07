/* CVE-2019-13066 — 堆溢出, 分配过小写入过大
 * 漏洞类型: 堆溢出 (直接大小不匹配)
 * 触发条件: 固定分配64字节, 写入128字节
 * 根因: malloc(64) + memcpy(buf, data, 128)
 * 有效原因: 常量不匹配, 区间分析应直接检出
 */
#include <stdlib.h>
#include <string.h>

void process_data(char *data, int datalen) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, data, 128);     /* 64 < 128: 确定溢出 */
    free(buf);
}

int main() {
    char input[256] = "AAAA";
    process_data(input, 256);
    return 0;
}
