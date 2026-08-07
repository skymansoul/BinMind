/* CWE-191: Underflow in realloc shrink → subsequent OOB write
 * newsize = cursize - delta where delta > cursize.
 * newsize underflows → realloc to huge → but old memcpy uses old size.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void trim_buffer(char *buf, int cursize, int delta) {
    int newsize = cursize - delta; /* underflow if delta > cursize */
    if (newsize < 0) return;
    char *newbuf = (char*)realloc(buf, newsize); /* huge alloc */
    if (!newbuf) return;
    memcpy(newbuf + newsize - 16, "metadata", 8); /* OOB if newsize underflowed */
    free(newbuf);
}
