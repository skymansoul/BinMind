#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2010_3089_mailto_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    size_t sz = (size_t)count * sizeof(int);
    if (sz < 4096) {  /* guard bypassed when sz wraps to 0 */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz > 0 ? sz : 4096);  /* write beyond alloc */
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2010_3089_mailto_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2010_3089_mailto_safe_vuln(1073741824);
    return 0;
}
