#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2022_42703_mm_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t addr = 0xFFFFFFFFFFFFFF00ULL;
    uint64_t len = (uint64_t)count;
    uint64_t end = addr + len;  /* wraps on 64-bit! */
    size_t sz = (size_t)(end - addr);
    if (sz == len && sz < 4096) {  /* sz!=len when wraps */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2022_42703_mm_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2022_42703_mm_safe_vuln(1073741824);
    return 0;
}
