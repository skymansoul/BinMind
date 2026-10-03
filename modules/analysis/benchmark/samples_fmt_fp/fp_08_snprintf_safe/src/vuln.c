#include <stdio.h>
int main(int argc, char **argv) {
    char out[128];
    snprintf(out, sizeof(out), "argc=%d", argc);
    printf("%s\n", out);
    return 0;
}
