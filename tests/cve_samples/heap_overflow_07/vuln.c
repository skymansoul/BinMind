/* heap_overflow_07 — 动态分配大小的堆溢出
 * 对应 CWE-122: malloc(N) where N is attacker-controlled
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(int user_size) {
    if (user_size <= 0 || user_size > 128) user_size = 128;
    char *buf = (char *)malloc(user_size);
    memset(buf, 'D', 256);  /* 无论 user_size 多少, 总是写 256 */
    free(buf);
}

int main(int argc, char **argv) {
    int n = 64;
    if (argc >= 2) n = atoi(argv[1]);
    process(n);
    return 0;
}
