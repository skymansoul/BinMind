#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2020_10757_mremap_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int nr_pages = count;
    if (nr_pages > 0xFFFFF) {
      printf("overflow rejected\n");
      return;
    }
    size_t sz = (size_t)nr_pages << 12;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_cve_2020_10757_mremap_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2020_10757_mremap_safe_safe(1073741824);
    return 0;
}
