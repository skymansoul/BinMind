/* TP-01: Direct Use-After-Free (CWE-416) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "sensitive data");
    free(buf);
    printf("%s\n", buf);  /* UAF: buf used after free */
}
int main(void) { process(); return 0; }