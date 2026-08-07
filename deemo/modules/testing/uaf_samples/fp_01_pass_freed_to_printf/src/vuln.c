#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    sprintf(p, "data");
    printf("[*] %s\n", p);
    free(p);
    printf("[*] freed %p\n", (void *)p);   /* 无害传递: 仅打印地址 */
    return 0;
}
