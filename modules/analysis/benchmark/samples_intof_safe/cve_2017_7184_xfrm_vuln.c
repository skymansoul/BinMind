#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2017_7184_xfrm_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint32_t offset = (uint32_t)count * 256U + 0xFFFFFF00U;  /* offset depends on count */
    uint32_t len = (uint32_t)(count + 256);
    uint32_t end = offset + len;  /* wraps when count large enough */
    if (end < offset) {  /* overflow detected: end wrapped around */
      char *buf = (char *)malloc(end);  /* end is small after wrap */
      if (!buf) return;
      memcpy(buf, "data", 4);  /* write to small buffer */
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2017_7184_xfrm_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2017_7184_xfrm_safe_vuln(1073741824);
    return 0;
}
