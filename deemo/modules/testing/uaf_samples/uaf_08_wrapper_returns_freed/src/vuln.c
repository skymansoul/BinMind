#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *make_temp(void) {
    char *p = (char *)malloc(64);
    if (!p) return NULL;
    strcpy(p, "temp");
    free(p);                       /* 释放后返回 */
    return p;
}
int main(void) {
    char *p = make_temp();
    if (!p) return 1;
    printf("[*] %s\n", p);         /* UAF: 悬空返回 */
    return 0;
}
