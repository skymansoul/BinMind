/* CWE-416: UAF with realloc shrinking - use old pointer after realloc */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(256);
    strcpy(buf, "original data in large buffer");
    char *newbuf = realloc(buf, 32); /* shrink: may return same or new ptr */
    if (newbuf) buf = newbuf;
    printf("%s\n", buf); /* ok if realloc succeeded */
    /* bug: if realloc moved the block, old data beyond 32B is lost */
    printf("byte 100: %c\n", buf[100]); /* read beyond realloc'd size */
    free(buf);
    return 0;
}
