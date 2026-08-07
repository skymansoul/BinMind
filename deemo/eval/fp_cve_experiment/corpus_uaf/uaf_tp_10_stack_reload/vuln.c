/* UAF-TP-10: free 后 mov rax,[rbp-8] 重载并写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(24);
    if (!p) return 1;
    memset(p, 'a', 8);
    free(p);
    char *r = p;
    r[0] = 'c';
    printf("%c\n", r[0]);
    return 0;
}
