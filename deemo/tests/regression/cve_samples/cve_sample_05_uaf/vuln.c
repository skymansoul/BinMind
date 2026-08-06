/* CVE-mimic: Use-after-free via dangling pointer
 * Real CVE: CVE-2023-3269 (kernel UAF)
 * Compile: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct obj { char data[64]; void (*cb)(void); };
void callback(void) { printf("callback
"); }
void vuln_fn(char *input) {
    struct obj *p = malloc(sizeof(struct obj));
    p->cb = callback;
    strcpy(p->data, input);
    free(p);
    p->cb();  /* UAF: p freed before callback invocation */
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vuln_fn(argv[1]);
    return 0;
}