/* VULN: snprintf(buf, wrong_size, ...) 其中 wrong_size > sizeof(buf) */
#include <stdio.h>
#include <stdlib.h>
void vuln(int count) {
    char buf[32];
    size_t wrong_size = (size_t)(count + 32);
    snprintf(buf, wrong_size, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
}
int main(int argc, char **argv) {
    vuln(argc > 1 ? atoi(argv[1]) : 65536);
    return 0;
}
