/* malloc(n) ¡ú write n+1 bytes (off-by-one) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *copy_str(const char *src, size_t len) {
    char *buf = (char *)malloc(len);
    if (!buf) return NULL;
    memcpy(buf, src, len);
    buf[len] = '\0';  /* BUG: writes beyond len */
    return buf;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <str>\n", argv[0]); return 1; }
    char *r = copy_str(argv[1], strlen(argv[1]));
    if (r) { printf("[*] %s\n", r); free(r); }
    return 0;
}
