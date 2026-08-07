/* Nested malloc: outer alloc based on len, inner loop uses more */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct record { size_t n; char **fields; };
static struct record *parse(const char *s) {
    struct record *r = (struct record *)malloc(sizeof(*r));
    if (!r) return NULL;
    size_t len = strlen(s);
    r->fields = (char **)malloc(len * sizeof(char *));
    r->n = len / 4 + 1;  /* BUG: n > len on small inputs */
    for (size_t i = 0; i < r->n; i++)
        r->fields[i] = strdup(s);
    return r;
}
int main(int argc, char **argv) {
    struct record *r = parse(argc > 1 ? argv[1] : "test");
    if (r) {
        for (size_t i = 0; i < r->n; i++) free(r->fields[i]);
        free(r->fields); free(r);
    }
    return 0;
}
