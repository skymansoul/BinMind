#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "hello");
    char *q = (char *)realloc(p, 4096);
    if (q) {
        p = q;                     /* 成功: 旧指针作废 */
    }
    printf("[*] %s\n", p);         /* 失败路径: p 仍有效 */
    free(p);
    return 0;
}
