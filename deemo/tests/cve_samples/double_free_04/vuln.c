/* double_free_04 — 循环内双重释放 (迭代导致重复free)
 * CWE-415: 循环控制错误导致同指针多次释放
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
int main() {
    char *p = malloc(64);
    for (int i = 0; i < 3; i++) free(p);
    return 0;
}
