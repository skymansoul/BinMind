/* CVE-2023-32233 (Linux nf_tables) UAF 复现 — nft 规则集释放后,
   匿名集合的 use 计数器仍被递减 (free 后写 *ptr). 简化:
   free(p) 后 *(int *)p = 0. */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *p;
    p = (int *)malloc(16);
    if (!p) {
        return 1;
    }
    *p = 5;
    free(p);
    *p = 0;
    return 0;
}
