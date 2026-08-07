/* CVE-2021-3156 sudo heap overflow — 模拟 sudoedit 缓冲区大小计算错误导致堆溢出 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_cmdline(char *user_input) {
    size_t alloc_sz = strlen(user_input) + 16;
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return;
    /* 漏洞: 拷贝时未计算 \\ 转义导致实际写入 > alloc_sz */
    char *d = buf;
    for (char *s = user_input; *s; s++) {
        if (*s == '\\') { *d++ = '\\'; *d++ = '\\'; }
        else *d++ = *s;
    }
    *d = '\0';
    /* d - buf 可能 > alloc_sz, 写入越过了分配边界 */
    printf("parsed: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    char input[] = "test\\\\user\\\\input\\\\overflow\\\\data\\\\extra";
    parse_cmdline(input);
    return 0;
}
