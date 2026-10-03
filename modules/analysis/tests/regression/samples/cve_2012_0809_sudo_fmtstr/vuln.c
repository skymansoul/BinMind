#include <stdio.h>
void debug(const char *prog, const char *msg) {
    fprintf(stderr, prog); /* BUG: prog from argv[0], used as format */
    fprintf(stderr, ": %s\n", msg);
}
int main(int a, char **v) { debug(v[0], "test"); return 0; }