#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2017_7184_xfrm_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint32_t offset = (uint32_t)count * 256U + 0xFFFFFF00U;
    uint32_t len = (uint32_t)(count + 256);
    if (len > UINT32_MAX - offset) {
      printf("overflow rejected\n");
      return;
    }
    uint32_t end = offset + len;
    char *buf = (char *)malloc(end);
    if (!buf) return;
    memcpy(buf, "data", 4);
    free(buf);
    printf("v_cve_2017_7184_xfrm_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2017_7184_xfrm_safe_safe(1073741824);
    return 0;
}
