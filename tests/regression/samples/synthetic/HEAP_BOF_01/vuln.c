#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *input) {
    size_t input_len = strlen(input);
    char *buf = malloc(64);
    if (!buf) return;
    memcpy(buf, input, input_len);  // input_len 可能 > 64
    buf[63] = '\0';
    printf("buf=%s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
