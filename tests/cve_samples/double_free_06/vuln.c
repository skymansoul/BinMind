/* double_free_06 — 信号处理器中双重释放
 * CWE-415: 信号异步触发导致释放竞争
 * 简化: 模拟信号处理中的重复释放
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
char *g_buf = NULL;
void handler() { if(g_buf) { free(g_buf); } }
int main() {
    g_buf = malloc(128);
    free(g_buf);
    handler(); /* g_buf未置NULL, 再次释放 */
    return 0;
}
