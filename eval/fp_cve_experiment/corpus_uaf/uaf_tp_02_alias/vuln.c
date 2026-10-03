/* UAF-TP-02: p/q 别名, free(p) 后 q[0] 写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(32);
    char *q = p;
    if (!p) return 1;
    strcpy(q, "alias");
    free(p);
    q[0] = 'Y';
    printf("%s\n", q);
    return 0;
}
