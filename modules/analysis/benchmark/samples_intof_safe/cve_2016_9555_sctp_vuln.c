#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2016_9555_sctp_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    ssize_t len = (ssize_t)count;  /* count is volatile, may be large */
    int narrow = (int)(unsigned int)count;  /* truncate then sign-extend */
    len = (ssize_t)narrow;
    size_t sz = (size_t)len;  /* negative -> huge size_t */
    if (sz > 0 && sz < 65536) {  /* bypassed: sz is huge */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, 16);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2016_9555_sctp_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2016_9555_sctp_safe_vuln(1073741824);
    return 0;
}
