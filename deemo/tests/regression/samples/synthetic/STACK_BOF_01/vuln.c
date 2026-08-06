#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // 无长度检查
    printf("copied: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vulnerable(argv[1]);
    return 0;
}
