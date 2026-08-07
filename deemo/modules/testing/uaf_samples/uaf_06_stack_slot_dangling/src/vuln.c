#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    char *saved = p;
    free(p);
    printf("[*] %s\n", saved);     /* UAF: 别名经栈槽使用 */
    return 0;
}
