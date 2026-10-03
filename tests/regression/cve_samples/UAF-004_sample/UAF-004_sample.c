/* UAF-004: Reuse after free — safe pattern, not UAF */
#include <stdlib.h>
#include <string.h>
void process(void) {
    char *buf = malloc(128);
    free(buf);
    buf = malloc(256);
    strcpy(buf, "safe reuse");
    free(buf);
}
int main(void) { process(); return 0; }
