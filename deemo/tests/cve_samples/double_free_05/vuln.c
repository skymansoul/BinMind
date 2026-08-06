/* double_free_05 — 错误处理路径中重复释放
 * CWE-415: goto错误处理标签时重复释放
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
void process(int mode) {
    char *buf = malloc(256);
    if (mode == 1) { free(buf); goto cleanup; }
    free(buf);
cleanup:
    free(buf); /* mode==1时重复释放 */
}
int main(int argc, char **argv) {
    process(argc > 1 ? 1 : 0);
    return 0;
}
