/* UAF-003: Conditionally freed — may or may not be UAF */
#include <stdlib.h>
#include <stdio.h>
void process(int flag) {
    char *buf = malloc(64);
    if (flag) { free(buf); buf = NULL; }
    if (buf) printf("%s", buf);
}
int main(void) { process(0); return 0; }
