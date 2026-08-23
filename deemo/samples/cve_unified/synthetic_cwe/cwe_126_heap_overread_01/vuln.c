/* CWE-126: Heap over-read (Heartbleed pattern) */
#include <stdlib.h>
#include <string.h>

void cwe126_overread(char *src, int user_length) {
    char *buf = (char *)malloc(user_length);
    if (buf) {
        memcpy(buf, src, user_length);  /* alloc == write �� over-read, not overflow */
        free(buf);
    }
}

int main(void) {
    char src[16] = "abcdefghijklmno";
    cwe126_overread(src, 64);  /* reads past 16-byte source */
    return 0;
}
