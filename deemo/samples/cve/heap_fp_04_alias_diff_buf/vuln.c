/* heap_fp_04: alias ptr to different buffer — ensemble should SUPPRESS
 * buf1=malloc(256); buf2=malloc(1024); ptr=buf2; memcpy(ptr, src, 512)
 * 512 <= 1024 (buf2) → safe; but forward analysis may bind ptr to buf1.
 */
#include <stdlib.h>
#include <string.h>
void process_two_bufs(char *src) {
    char *buf1 = (char*)malloc(256);
    char *buf2 = (char*)malloc(1024);
    if (!buf1 || !buf2) return;
    char *ptr = buf2;              /* ptr aliases buf2, NOT buf1 */
    memcpy(ptr, src, 512);        /* 512B into buf2(1024B) → safe */
    free(buf1); free(buf2);
}
