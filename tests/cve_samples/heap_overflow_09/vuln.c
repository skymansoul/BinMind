/* heap_overflow_09 — 多级指针导致中间缓冲区溢出
 * CWE-122: 中间指针写入超过分配
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void nested_write(const char *input) {
    char *outer = malloc(32);
    char *inner = outer + 8;  /* 内部指针指向outer偏移8 */
    strcpy(inner, input);     /* 若input>24则溢出outer边界 */
    free(outer);
}
int main(int argc, char **argv) {
    nested_write(argc>1 ? argv[1] : "short");
    return 0;
}
