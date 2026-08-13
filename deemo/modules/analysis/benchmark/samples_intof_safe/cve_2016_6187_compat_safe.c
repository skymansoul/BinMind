#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2016_6187_compat_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t num_entries = (uint64_t)count * 7ULL + 0x100000001ULL;
    if (num_entries > UINT32_MAX) {
      printf("overflow rejected\n");
      return;
    }
    uint32_t count32 = (uint32_t)num_entries;
    size_t sz = count32 * sizeof(int);
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_cve_2016_6187_compat_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2016_6187_compat_safe_safe(1073741824);
    return 0;
}
