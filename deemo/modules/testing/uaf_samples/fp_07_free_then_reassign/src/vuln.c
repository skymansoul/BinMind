#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);          /* ÷ÿ∏≥÷µ */
    if (!p) return 1;
    strcpy(p, "new");
    printf("[*] %s\n", p);
    free(p);
    return 0;
}
