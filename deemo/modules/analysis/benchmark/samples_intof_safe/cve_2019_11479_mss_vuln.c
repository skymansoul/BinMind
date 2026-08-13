#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2019_11479_mss_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint16_t total = 0;
    int n = count;
    for (int i = 0; i < n; i++) {
      total += 64;  /* wraps when n>1024 */
    }
    if (total > 0 && total < 8192) {
      char *buf = (char *)malloc(total);
      if (!buf) return;
      memset(buf, 0, total);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2019_11479_mss_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2019_11479_mss_safe_vuln(1073741824);
    return 0;
}
