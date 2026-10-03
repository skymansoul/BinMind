/* TN-04: Realloc Self-Assign Safe (SAFE) */
#include <stdlib.h>
#include <string.h>
void realloc_self_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    strcpy(p, "init");
    p = (char *)realloc(p, 128);
    strcat(p, " extended");
    free(p);
}
int main(void) { realloc_self_safe(); return 0; }