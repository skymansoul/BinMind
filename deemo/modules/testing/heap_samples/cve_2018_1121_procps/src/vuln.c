/* CVE-2018-1121 — procps sort key heap overflow (unbounded strcpy) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct row { char key[64]; int val; };
static struct row *make_row(const char *key) {
    struct row *r = (struct row *)malloc(sizeof(struct row));
    if (!r) return NULL;
    strcpy(r->key, key);  /* BUG: key may exceed 63 bytes */
    r->val = 1;
    return r;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <key>\n", argv[0]); return 1; }
    struct row *r = make_row(argv[1]);
    if (r) { printf("[*] %s %d\n", r->key, r->val); free(r); }
    return 0;
}
