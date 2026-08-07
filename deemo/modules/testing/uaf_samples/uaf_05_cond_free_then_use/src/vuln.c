#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) {
        free(p);                   /* 条件释放 */
    }
    printf("[*] %s\n", p);         /* UAF: 释放路径仍使用 */
    return 0;
}
