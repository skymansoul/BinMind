/* VULN: alloca(s) 然后 memset(p, 0, s*2) */
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int s = argc > 1 ? atoi(argv[1]) : 1024;
    char *p = alloca(s);
    memset(p, 0, s * 2);
    return 0;
}
