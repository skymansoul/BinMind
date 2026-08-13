#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2016_9555_sctp_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    ssize_t len = (ssize_t)count;
    if (len < 0 || len > 65536) {
      printf("invalid len\n");
      return;
    }
    size_t sz = (size_t)len;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_cve_2016_9555_sctp_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2016_9555_sctp_safe_safe(1073741824);
    return 0;
}
