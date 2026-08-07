/* CVE-2021-4034 polkit pkexec: 固定16字节堆缓冲, argv 数据 memcpy 超限.
 * 触发: 固定 16 字节堆缓冲, memcpy 写入长度由输入决定.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(16);
    if (!buf) return 1;
    memcpy(buf, argv[2], len);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
    return 0;
}
