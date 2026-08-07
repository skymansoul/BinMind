/* CVE-2020-36709 — 堆溢出, strncpy写入固定大小
 * 漏洞类型: 堆溢出 (strncpy长度不匹配)
 * 触发条件: malloc(src_len), strncpy(buf, src, src_len*2)
 * 根因: 分配src_len, strncpy用2*src_len
 * 有效原因: 测试乘法缩放的符号表达式追踪
 */
#include <stdlib.h>
#include <string.h>

void double_size_copy(char *src) {
    size_t len = strlen(src);
    char *buf = (char *)malloc(len);       /* 分配len */
    if (!buf) return;
    strncpy(buf, src, len * 2);            /* 写入2*len: 溢出len字节 */
    buf[len * 2] = '\0';
    free(buf);
}

int main() {
    char data[64] = "hello";
    double_size_copy(data);
    return 0;
}
