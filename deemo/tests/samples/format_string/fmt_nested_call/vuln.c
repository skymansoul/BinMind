#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-12: 嵌套调用 — 格式串经过多层函数传递 */
void inner(const char *s) { printf(s); }  /* 可能危险 */
void outer(const char *input) { inner(input); }  /* 透传 */

int main(int argc, char **argv) {
    if (argc > 1) outer(argv[1]);  /* VULNERABLE: 用户输入到printf */
    else outer("safe: %d\n");
    return 0;
}
