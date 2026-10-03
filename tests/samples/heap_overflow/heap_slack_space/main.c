/* heap_slack_space: write within malloc chunk slack space.
   malloc(100) → glibc provides ~104 usable bytes on x86_64.
   Write at offset 100 for 4 bytes should be SAFE (within chunk).
   Designed to test allocator_chunk_model.py slack detection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(100);
    if (!buf) return 1;
    buf[100] = 'S';  /* within slack — should be filtered */
    buf[101] = 'L';
    buf[102] = 'A';
    buf[103] = 'C';
    printf("slack test: %c%c%c%c\n", buf[100], buf[101], buf[102], buf[103]);
    free(buf);
    return 0;
}
