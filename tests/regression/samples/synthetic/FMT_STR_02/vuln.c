#include <stdio.h>

void error_out(char *msg) {
    fprintf(stderr, msg);  // msg 来自用户输入
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    error_out(argv[1]);
    return 0;
}
