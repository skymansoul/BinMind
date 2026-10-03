#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2019_11479_mss_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int n = count;
    if (n > 1024) {  /* 1024*64=65536 -> wraps u16 */
      printf("overflow rejected\n");
      return;
    }
    uint16_t total = 0;
    for (int i = 0; i < n; i++) total += 64;
    char *buf = (char *)malloc(total);
    if (!buf) return;
    memset(buf, 0, total);
    free(buf);
    printf("v_cve_2019_11479_mss_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2019_11479_mss_safe_safe(1073741824);
    return 0;
}
