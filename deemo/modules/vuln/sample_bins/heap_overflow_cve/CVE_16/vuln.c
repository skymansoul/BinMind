/* CVE-2021-39514 (安全陷阱) — 对齐padding内写入
 * 漏洞类型: 无溢出 (glibc可用量吸收小偏移)
 * 触发条件: malloc(62) → glibc chunk可用48字节, 写入48字节
 * 根因: 无漏洞; 分配器对齐导致请求62字节实际可用更多
 * 有效原因: 测试AWSC同源+分配器padding判定能否消除误报
 */
#include <stdlib.h>
#include <string.h>

void safe_padding(char *input, size_t n) {
    /* malloc(62): glibc实际chunk对齐后可用量>62 */
    char *buf = (char *)malloc(62);
    if (!buf) return;
    size_t len = n < 48 ? n : 48;
    memcpy(buf, input, len);   /* len<=48, 在可用量内, 安全 */
    free(buf);
}

int main() {
    char data[128] = "AAAABBBBCCCCDDDD";
    safe_padding(data, 48);
    return 0;
}
