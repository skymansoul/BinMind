#include <stdio.h>
#include <string.h>

void process(char *user_input) {
    char buf[32];
    sprintf(buf, "prefix_%s_suffix", user_input);  // user_input 可能很长
    printf("result: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
