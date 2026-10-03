#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2014_2851_ping_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint16_t c16 = (uint16_t)count;
    size_t sz = (size_t)c16 * sizeof(int);  /* Correct: promote BEFORE mul */
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_cve_2014_2851_ping_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2014_2851_ping_safe_safe(1073741824);
    return 0;
}
