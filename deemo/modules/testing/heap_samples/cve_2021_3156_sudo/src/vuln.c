/* CVE-2021-3156 — sudoedit heap overflow (size mismatch) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *set_cmnd(const char *src, size_t raw_size) {
    size_t safe_size = (raw_size > 255) ? 255 : raw_size;
    char *buf = (char *)malloc(safe_size + 1);
    if (!buf) return NULL;
    memcpy(buf, src, raw_size);  /* BUG: uses raw_size, not safe_size */
    buf[raw_size] = '\0';
    return buf;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 1; }
    char *r = set_cmnd(argv[1], strlen(argv[1]));
    if (r) { printf("[*] %s\n", r); free(r); }
    return 0;
}
