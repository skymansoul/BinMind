#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2013_1959_userns_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t kuid = (uint64_t)count * 0x10000001ULL;
    if (kuid < (uint64_t)count) {  /* wrapped in 64-bit? should not happen */
      printf("overflow rejected\n");
      return;
    }
    if (kuid > (UINT32_MAX / 16)) {
      printf("overflow rejected\n");
      return;
    }
    uint32_t uid = (uint32_t)kuid;
    int ngroups = (int)uid;
    char *buf = (char *)malloc(ngroups * 8 + 1);
    if (!buf) return;
    memset(buf, 0, ngroups * 8 + 1);
    free(buf);
    printf("v_cve_2013_1959_userns_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2013_1959_userns_safe_safe(1073741824);
    return 0;
}
