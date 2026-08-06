/* CWE-122: calloc->memcpy with integer overflow in size calc
   Simulates CVE-2015-7547 getaddrinfo stack-to-heap pattern */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(int count, char *data) {
    size_t total = count * sizeof(char);  /* may overflow */
    char *buf = calloc(count, 1);
    if (!buf) return;
    memcpy(buf, data, count);  /* count may be attacker-controlled */
    printf("copied %d bytes\n", count);
    free(buf);
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 256;
    process(n, "AAAA");
    return 0;
}
