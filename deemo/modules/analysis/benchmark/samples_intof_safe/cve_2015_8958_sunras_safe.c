#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2015_8958_sunras_safe_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int rows = count;
    int cols = count;
    size_t total = (size_t)rows * (size_t)cols;  /* promote BEFORE mul */
    if (total > 65536) {
      printf("too large\n");
      return;
    }
    char *buf = (char *)malloc(total);
    if (!buf) return;
    memset(buf, 0, total);
    free(buf);
    printf("v_cve_2015_8958_sunras_safe: ok\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2015_8958_sunras_safe_safe(1073741824);
    return 0;
}
