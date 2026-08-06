/* stack_overflow_02 — strcpy 目标缓冲区小于源
 * 对应 CWE-121: 固定大小栈缓冲区 + 无长度检查的 strcpy
 * 编译: gcc -o vuln vuln.c -fno-stack-protector
 */
#include <stdio.h>
#include <string.h>

void copy_name(const char *name) {
    char local[32];
    strcpy(local, name);  /* 溢出: name 可能 > 32 字节 */
    printf("name: %s\n", local);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    copy_name(argv[1]);
    return 0;
}
