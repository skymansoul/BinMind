#include <stdio.h>
#include <stdlib.h>
/* FMT-01: 用户输入直接作为格式串 — 经典fmt漏洞 */
int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <fmt>\n", argv[0]); return 1; }
    printf(argv[1]);  /* VULNERABLE: 用户控制格式串 */
    return 0;
}
