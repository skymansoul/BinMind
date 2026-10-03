/* 多变量独立溢出: malloc(n)+memcpy(atoi(argv)) — write来自用户输入, 与alloc无关 */
#include <stdlib.h>
#include <string.h>
void multivar_overflow(int n, int argc, char **argv) {
    char *buf = malloc(n);
    if (!buf) return;
    int m = atoi(argv[1]);
    memcpy(buf, src, m);
    free(buf);
}
