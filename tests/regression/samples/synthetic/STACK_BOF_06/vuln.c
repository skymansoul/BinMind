/* CWE-121: Stack overflow via alloca with user-controlled size */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
void process(int n, char *src) {
    char *buf = alloca(n); /* n is user-controlled, stack alloc */
    memcpy(buf, src, n);
}
int main(int argc, char **argv) {
    process(argc>1?atoi(argv[1]):99999, "A");
    return 0;
}
