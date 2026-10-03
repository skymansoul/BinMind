#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[128];
    const char *input = argc > 1 ? argv[1] : "default";
    /* SAFE: constant format, bounded output */
    snprintf(buf, sizeof(buf), "Input: %s", input);
    printf("%s\n", buf);
    return 0;
}
