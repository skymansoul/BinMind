/* CVE-2018-14634 Linux create_elf_tables: 参数乘积回绕导致小分配+大写入.
 * 触发: 分配大小按 count*16, 写入大小按 count*32 增长更快;
 * 真实CVE经整数回绕使分配收缩, 此处保留静态可判的增长关系.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int count = (unsigned int)atoi(argv[1]);
    size_t sz = (size_t)count * 16;
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memcpy(buf, argv[2], (size_t)count * 32);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
    return 0;
}
