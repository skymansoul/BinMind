#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2022_42703_mm_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t addr = 0xFFFFFFFFFFFFFF00ULL;
    uint64_t len = (uint64_t)count;
    if (len > UINT64_MAX - addr) {
      printf("overflow rejected\n");
      return;
    }
    uint64_t end = addr + len;
    size_t sz = (size_t)(end - addr);
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_cve_2022_42703_mm_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2022_42703_mm_safe_safe(1073741824);
    return 0;
}
