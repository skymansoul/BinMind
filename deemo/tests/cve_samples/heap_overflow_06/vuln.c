/* heap_overflow_06 — free后重用指针但已重新分配更小块
 * 对应 CWE-416 + CWE-122 混合场景
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *g_ptr = NULL;

int main() {
    g_ptr = (char *)malloc(128);
    free(g_ptr);
    g_ptr = (char *)malloc(32);  /* 重新分配更小 */
    memset(g_ptr, 'C', 64);       /* 写入 64 > 32 */
    free(g_ptr);
    return 0;
}
