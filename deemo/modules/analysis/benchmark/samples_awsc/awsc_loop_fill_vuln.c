/** awsc_loop_fill_vuln: OVERFLOW: loop cumulative 5*64 > alloc 256 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    for (int i = 0; i < 5; i++) {
        memcpy(buf + i * 64, payload, 64);
    }
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(); return 0; }
