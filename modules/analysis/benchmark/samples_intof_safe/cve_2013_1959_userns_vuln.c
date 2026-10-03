#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2013_1959_userns_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t kuid = (uint64_t)count * 0x10000001ULL;  /* large factor */
    uint32_t uid = (uint32_t)kuid;  /* truncation! */
    int ngroups = (int)uid;  /* truncated value: small when count*mult wraps to <2^31 */
    if (ngroups > 0 && ngroups < 65536) {  /* bypassed */
      char *buf = (char *)malloc(ngroups * 8 + 1);
      if (!buf) return;
      memset(buf, 0, ngroups * 8 + 1);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2013_1959_userns_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2013_1959_userns_safe_vuln(1073741824);
    return 0;
}
