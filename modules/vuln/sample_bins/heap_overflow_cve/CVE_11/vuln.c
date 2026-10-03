/* CVE-2016-0718 — 堆溢出, read()返回值用作长度
 * 漏洞类型: 堆溢出 (外部输入决定写入长度)
 * 触发条件: malloc(fixed_size), memcpy(buf, src, read_return)
 * 根因: 分配64, read返回>64时溢出, 且无bounds check
 * 有效原因: 测试外部输入感知的后向切片追踪
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void process_input(int fd) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    char tmp[256];
    int n = read(fd, tmp, 256);   /* 外部输入: n ∈ [0, 256] */
    if (n > 0) {
        memcpy(buf, tmp, n);       /* n可能>64: 溢出 */
    }
    free(buf);
}

int main() {
    process_input(0);
    return 0;
}
