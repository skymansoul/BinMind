/* CVE-2017-14492 ¡ª dnsmasq: small alloc + unbounded name copy */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *check_for_bogus_wildcard(const char *name) {
    char *p = (char *)malloc(32);       /* fixed small buffer */
    if (!p) return NULL;
    strcpy(p, name);                    /* BUG: unbounded */
    return p;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <name>\n", argv[0]); return 1; }
    char *p = check_for_bogus_wildcard(argv[1]);
    if (p) { printf("[*] %s\n", p); free(p); }
    return 0;
}
