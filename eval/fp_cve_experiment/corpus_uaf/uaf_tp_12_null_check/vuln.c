/* UAF-TP-12: free(p) 后 if(p) p[0] 使用 — NULL检查不防护, 必须检出. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    free(p);
    if (p) {
        p[0] = 'N';
    }
    printf("%d\n", p[0]);
    return 0;
}
