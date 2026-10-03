/* CVE-2017-1000112: Linux IPv6 UFO 堆溢出 —— 简化 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void build_ipv6_fragment(char **frags, int nfrags) {
    int total = 0;
    for(int i=0;i<nfrags;i++) total+=strlen(frags[i]);
    char *buf = malloc(total);
    /* BUG: total 未校验是否超过合理上界 */
    char *p = buf;
    for(int i=0;i<nfrags;i++) { strcpy(p, frags[i]); p+=strlen(frags[i]); }
    free(buf);
}
int main() { char *f[]={"AAAA","BBBB","CCCC"}; build_ipv6_fragment(f,3); return 0; }
