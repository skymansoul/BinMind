#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

void v_cve_2015_8958_sunras_safe_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int rows = count;
    int cols = count;
    int total = rows * cols;  /* signed overflow -> UB! */
    if (total > 0 && total < 8192) {
      char *buf = (char *)malloc(total);
      if (!buf) return;
      memset(buf, 0, total);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_cve_2015_8958_sunras_safe: done\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    v_cve_2015_8958_sunras_safe_vuln(1073741824);
    return 0;
}
