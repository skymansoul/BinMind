/* INT-0009: Integer overflow variant */
#include <stdlib.h>
#include <stdio.h>
void process(int n, int m) {
    size_t total = n * m;
    char *p = malloc(total);
    if (p) { p[0] = 'x'; free(p); }
}
int main(void) { process(65536, 65536); return 0; }
