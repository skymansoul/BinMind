
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_func(char *user_input) {
    char *buf = malloc(32);
    memcpy(buf, user_input, 128);
    printf(buf);
    free(buf);
    free(buf);
}
int main(int argc, char *argv[]) {
    vuln_func(argv[1]);
    return 0;
}
