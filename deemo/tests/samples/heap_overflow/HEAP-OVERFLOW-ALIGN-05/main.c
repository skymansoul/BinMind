/* HEAP-OVERFLOW-ALIGN-05: malloc(100) → glibc gives ~104 usable bytes.
   Store at offset 100 with size 4 (ends at 104). SAFE — within aligned chunk.
   Naive detector comparing offset(100) > alloc(100) would flag this. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(100);
    if (!buf) return 1;
    memset(buf, 0, 96);
    buf[96] = 'A'; buf[97] = 'B'; buf[98] = 'C'; buf[99] = 'D';
    *(int*)(buf + 100) = 0x41424344;  /* offset 100, aligned chunk has 104+ */
    printf("ok\n");
    free(buf);
    return 0;
}
