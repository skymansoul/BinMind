#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int process(char *p) {
    if (!p) return -1;
    size_t len = strlen(p);
    if (len > 100) {
        free(p);                   /* 超长 → 释放并返回 */
        return -1;
    }
    printf("[*] %s (%zu)\n", p, len);  /* 正常路径使用 — 与 free 互斥 */
    return 0;
}
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) strcpy(p, argv[1]);
    else strcpy(p, "short");
    int rc = process(p);
    if (rc == 0) free(p);
    return 0;
}
