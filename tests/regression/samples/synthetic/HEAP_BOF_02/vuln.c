#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *input) {
    size_t len = strlen(input);
    char *buf = malloc(32);
    buf = realloc(buf, 32);
    strncpy(buf, input, len);  // len 可能 > 32
    buf[31] = '\0';
    printf("buf=%s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
