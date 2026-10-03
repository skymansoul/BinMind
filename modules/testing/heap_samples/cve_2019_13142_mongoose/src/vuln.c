/* CVE-2019-13142 — Mongoose OS Content-Disposition heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int parse_name(const char *header, char **out) {
    const char *s = strstr(header, "name=\"");
    if (!s) return -1;
    s += 6;
    const char *e = strchr(s, '"');
    if (!e) return -1;
    size_t len = (size_t)(e - s);
    *out = (char *)malloc(len);  /* BUG: should be len+1 */
    if (!*out) return -1;
    memcpy(*out, s, len);
    (*out)[len] = '\0';  /* writes one byte past allocation */
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <header>\n", argv[0]); return 1; }
    char *name = NULL;
    if (parse_name(argv[1], &name) == 0) { printf("[*] %s\n", name); free(name); }
    return 0;
}
