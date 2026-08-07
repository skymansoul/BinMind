#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    free(p);
    p[0] = 'X';                    /* UAF: Ğ´ÒÑÊÍ·ÅÄÚ´æ */
    printf("[*] %c\n", p[0]);
    return 0;
}
