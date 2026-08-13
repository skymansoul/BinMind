#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2020_10757_mremap_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int nr_pages = count;
    size_t sz = (size_t)(nr_pages << 12);  /* wraps when nr>=0x100000 */
    if (sz > 0 && sz < 0x100000) {
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2020_10757_mremap_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2020_10757_mremap_safe_vuln(1073741824);
    return 0;
}
