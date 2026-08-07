/* CVE-2018-1000001 cURL TFTP: 按包长参数分配, 收到更大块时写入超限.
 * 触发: 分配大小依赖输入参数, 写入大小为其2倍.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t n = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    memcpy(buf, argv[2], n * 2);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
    return 0;
}
