/* CVE-2018-20735 ¡ª libsass: copied_length vs allocated field */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sass_value { char *str; size_t str_len; };
static struct sass_value *valloc(const char *s, size_t decl_len) {
    struct sass_value *v = (struct sass_value *)malloc(sizeof(*v));
    if (!v) return NULL;
    v->str = (char *)malloc(decl_len);  /* declared (too small) */
    if (!v->str) { free(v); return NULL; }
    size_t real = strlen(s) + 1;
    v->str_len = real;
    memcpy(v->str, s, real);            /* BUG: real > decl_len */
    return v;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <str>\n", argv[0]); return 1; }
    struct sass_value *v = valloc(argv[1], 16);
    if (v) { printf("[*] len=%zu\n", v->str_len); free(v->str); free(v); }
    return 0;
}
