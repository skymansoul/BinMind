#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p1 = (char *)malloc(16);
    char *p2 = (char *)malloc(256);
    if (!p1 || !p2) return 1;
    memcpy(p2, "0123456789abcdef0123456789abcdef", 32);  /* Ä¿±êÊÇ p2, 128>=32 */
    printf("[*] %s %s\n", p1, p2);
    free(p1); free(p2);
    return 0;
}
