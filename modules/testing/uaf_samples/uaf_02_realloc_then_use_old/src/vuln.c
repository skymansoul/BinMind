#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "hello");
    char *q = (char *)realloc(p, 4096);
    if (!q) return 1;
    printf("[*] %s\n", p);         /* UAF: realloc 成功后旧指针已释放 */
    free(q);
    return 0;
}
