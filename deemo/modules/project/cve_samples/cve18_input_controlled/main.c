// cve18_input_controlled — 输入控制: malloc(128)→memset(atoi(argv[1])), argv控制大小
// CVE参考: CVE-2021-33286, 模式: input_controlled
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 写入大小来自argv, 可能大于分配
    int write_size = 128;
    if (argc > 1) write_size = atoi(argv[1]);
    if (write_size <= 0) write_size = 128;

    memset(buf, 'A', write_size);

    printf("buf=%p, wrote %d into %d-byte buff\n",
           (void *)buf, write_size, ALLOC_SIZE);
    free(buf);
    return 0;
}
