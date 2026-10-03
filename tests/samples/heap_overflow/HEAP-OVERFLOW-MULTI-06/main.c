/* HEAP-OVERFLOW-MULTI-06: multiple mallocs; only one overflows.
   Tests precision: the 64B overflow on buf2 should be caught;
   buf1(128) and buf3(256) writes are safe. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf1 = malloc(128);
    char *buf2 = malloc(64);
    char *buf3 = malloc(256);
    if (!buf1 || !buf2 || !buf3) return 1;
    memset(buf1, 'A', 128);   /* safe */
    memset(buf2, 'B', 256);   /* overflow: 64→256 */
    memset(buf3, 'C', 256);   /* safe */
    printf("multi: %c %c %c\n", buf1[0], buf2[0], buf3[0]);
    free(buf1); free(buf2); free(buf3);
    return 0;
}
