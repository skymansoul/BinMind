/* CVE-2021-22600 (Linux netfilter) UAF 复现 — 规则释放后规则链
   的遍历器仍解引用已释放条目. 简化: free(p) 后 memcpy 读 p. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p;
    char out[16];
    p = (char *)malloc(16);
    if (!p) {
        return 1;
    }
    memset(p, 'a', 16);
    free(p);
    memcpy(out, p, 16);
    printf("%s\n", out);
    return 0;
}
