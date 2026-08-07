/* CVE-2021-3156 (简化版) — sudo堆溢出
 * 漏洞类型: 堆溢出 (off-by-one → 堆元数据覆盖)
 * 触发条件: 特殊构造的argv[0]触发sudo堆溢出
 * 根因: malloc(size)后memcpy写入size+1字节, off-by-one
 * 有效原因: 分配大小与写入大小的经典off-by-one不一致
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void vulnerable_parse(char *input) {
    size_t len = strlen(input);
    char *buf = malloc(len);          /* 分配len字节 */
    if (!buf) return;
    memcpy(buf, input, len + 1);      /* 写入len+1字节: off-by-one */
    printf("%s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc > 1) vulnerable_parse(argv[1]);
    return 0;
}
