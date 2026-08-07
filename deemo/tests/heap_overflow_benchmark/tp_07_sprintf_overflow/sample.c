/*
 * TP-07: sprintf Format Overflow to Heap (CWE-134+CWE-122)
 *
 * malloc(32) → sprintf生成超过32B的格式化输出 → 堆溢出
 * 格式化字符串输出长度不可预测, 超出缓冲区
 *
 * 真实漏洞类比: CVE-2021-3156 (sudo Baron Samedit堆溢出)
 */
#include <stdlib.h>
#include <stdio.h>

int log_message(const char *user_input) {
    char *buf = (char *)malloc(32);
    if (!buf) return -1;

    /* sprintf无界写入: 输出可能远超32B */
    sprintf(buf, "User data: %s", user_input);

    free(buf);
    return 0;
}

int main(void) {
    return log_message("AAAA...<256 bytes of padding>...BBBB");
}
