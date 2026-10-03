/* CVE-2019-3462 Debian apt signedby: 按哈希长度分配, 写入 len+1 溢出1字节.
 * 触发: 按参数长度分配, memcpy 写入 len+1 字节 (off-by-one).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    memcpy(buf, argv[2], len + 1);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
    return 0;
}
