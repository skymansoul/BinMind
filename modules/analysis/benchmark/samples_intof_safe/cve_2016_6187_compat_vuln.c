#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2016_6187_compat_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t num_entries = (uint64_t)count * 7ULL + 0x100000001ULL;
    uint32_t count32 = (uint32_t)num_entries;  /* truncation! */
    size_t sz = (size_t)count32 * sizeof(int);
    if (sz < 65536) {  /* bypassed: count32 is small */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      for (uint64_t i = 0; i < num_entries && i < 100; i++) buf[i] = 0;
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2016_6187_compat_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2016_6187_compat_safe_vuln(1073741824);
    return 0;
}
