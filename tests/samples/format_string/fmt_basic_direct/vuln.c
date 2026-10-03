#include <stdio.h>
#include <stdlib.h>
/* FMT-01: 直接用户输入作为格式字符串 — 最经典格式字符串漏洞
 * 攻击者可提供%s/%x/%n等格式说明符 */
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);  /* VULNERABLE: 用户输入直接作为格式字符串 */
    return 0;
}
