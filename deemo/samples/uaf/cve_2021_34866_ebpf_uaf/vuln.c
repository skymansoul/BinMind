/*
 * cve_2021_34866 — Linux eBPF UAF (CWE-416)
 * 模式: 别名指针释放后经原指针读取.
 * 原漏洞: eBPF verifier 对 register 复用判断缺陷, 导致释放后使用.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void proc(char *input) {
    char *a1 = malloc(128); char *a2 = a1;
    memcpy(a1, input, 128);
    free(a2); /* BUG: a1 still references freed memory */
    printf("out: %s", a1); /* UAF */
}
int main(int a, char **v) { char d[128]; memset(d, 'C', 128); proc(d); return 0; }
