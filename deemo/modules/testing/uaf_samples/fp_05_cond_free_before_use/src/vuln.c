#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) {
        free(p);                   /* 条件释放 */
        p = NULL;
    }
    if (p) printf("[*] %c\n", p[0]);   /* 未释放路径才使用 */
    return 0;
}
