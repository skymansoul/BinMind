/**
 * sawce_loop_accumulate - malloc(256); loop 5x memcpy(p+offset, src, 64) - cumulative 320 > 256
 *
 * Stage 10 test: loop accumulation overflow.
 * Each iteration writes 64 bytes (safe), but 5 iterations = 320 > 256.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[512];

void sawce_loop_accumulate_vuln(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    char *ptr = buf;
    int i;
    /* BUG: 5 * 64 = 320 > 256 allocation */
    for (i = 0; i < 5; i++) {
        memcpy(ptr, payload, 64);
        ptr += 64;
    }
    printf("sawce_loop_accumulate: loop accumulate overflow\n");
    free(buf);
}

/* Safe: 3 iterations * 64 = 192 <= 256 */
void sawce_loop_accumulate_safe(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    char *ptr = buf;
    int i;
    for (i = 0; i < 3; i++) {
        memcpy(ptr, payload, 64);
        ptr += 64;
    }
    printf("sawce_loop_accumulate_safe: ok\n");
    free(buf);
}

int main(void) {
    memset(payload, 'A', sizeof(payload));
    sawce_loop_accumulate_vuln();
    sawce_loop_accumulate_safe();
    return 0;
}
