#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2019_19332_kvm_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    size_t nmemb = (size_t)count;
    size_t elem_size = 16;
    size_t total = nmemb * elem_size;  /* wraps silently! */
    if (total < 65536 && total > 0) {
      char *buf = (char *)calloc(1, total);
      if (!buf) return;
      memset(buf, 0, total > 0 ? total : 65536);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2019_19332_kvm_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2019_19332_kvm_safe_vuln(1073741824);
    return 0;
}
