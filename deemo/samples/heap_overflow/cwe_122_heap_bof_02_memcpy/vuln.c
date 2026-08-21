/* CWE-122: memcpy with attacker-controlled size */
#include <stdlib.h>
#include <string.h>

void cwe122_memcpy(char *src, int user_len) {
    char *buf = (char *)malloc(64);
    if (buf && user_len > 0) {
        memcpy(buf, src, user_len);  /* user_len may exceed 64 �� OVERFLOW */
        free(buf);
    }
}

int main(void) {
    static char src[200];
    cwe122_memcpy(src, 100);  /* 100 > 64 */
    return 0;
}
