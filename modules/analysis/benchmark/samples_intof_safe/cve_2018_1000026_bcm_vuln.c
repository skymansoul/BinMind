#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2018_1000026_bcm_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int shift = count % 64;  /* could be 32..63 */
    int sz = 1 << shift;  /* wraps to 0/negative */
    if (sz > 0 && sz < 4096) {
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, abs(sz));
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2018_1000026_bcm_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2018_1000026_bcm_safe_vuln(1073741824);
    return 0;
}
