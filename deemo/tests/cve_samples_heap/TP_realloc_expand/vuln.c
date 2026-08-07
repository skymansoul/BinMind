/*
 * TP_realloc_expand: realloc with larger size after initial alloc.
 * The write is at an offset that would overflow the ORIGINAL allocation,
 * but realloc expanded the buffer → safe.
 *
 * Pattern: p=malloc(32); p=realloc(p,128); store(p+100,x);
 * Naive detector sees store(offset=100) > original alloc(32) → FP.
 * GAPSBV should track the realloc and use the expanded size.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void expand_and_write(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return;

    /* Simulate needing more space */
    buf = (char *)realloc(buf, 128);
    if (!buf) return;

    /* Write at offset 100 — safe because realloc expanded to 128 */
    memset(buf + 100, 'X', 20);
    buf[119] = '\0';

    printf("buf+100 = %s\n", buf + 100);
    free(buf);
}

int main(void) {
    expand_and_write();
    return 0;
}
