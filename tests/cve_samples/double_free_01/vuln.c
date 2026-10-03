/* double_free_01 — 同一指针被两次 free
 * 对应 CWE-415: Double Free
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>

void process(char *data) {
    free(data);
    /* ... some logic ... */
    free(data);  /* double free: data 已被释放 */
}

int main() {
    char *p = (char *)malloc(256);
    process(p);
    return 0;
}
