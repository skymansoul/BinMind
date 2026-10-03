#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-04: 条件释放 — 一条路径free另一条不free, 汇合点use */
int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    strcpy(buf, "conditional_data");
    if (argc > 1) { free(buf); }
    printf("cond use: %s\n", buf);  /* VULNERABLE if argc>1 */
    if (argc <= 1) free(buf);
    return 0;
}
