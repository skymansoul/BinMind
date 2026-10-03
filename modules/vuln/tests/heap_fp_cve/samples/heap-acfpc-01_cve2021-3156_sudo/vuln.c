/* CVE-2021-3156 (sudo Baron Samedit) 堆溢出复现 — 非堆溢出的根本是 argv 处理
   中 strncpy 长度 n+1 造成的 off-by-one 写入. 此处简化为直接表达该模式:
   alloc(len) 后 memcpy 写 len+1 字节, 恰好越出 1 字节. 该 off-by-one 无法
   被对齐过滤覆盖 (len+1 > usable(len) 恒成立), 属 ACFPC 的 CONFIRM 路径. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_command(char *dst, const char *src, size_t len) {
    memcpy(dst, src, len + 1);
}

int main(int argc, char **argv) {
    size_t len;
    char *buf;
    if (argc < 2) {
        return 0;
    }
    len = strlen(argv[1]);
    buf = (char *)malloc(len);
    if (!buf) {
        return 1;
    }
    copy_command(buf, argv[1], len);
    printf("%s\n", buf);
    free(buf);
    return 0;
}
