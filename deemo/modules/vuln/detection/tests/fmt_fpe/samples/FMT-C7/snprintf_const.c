
/* 良性: snprintf 常量格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    char out[64];
    snprintf(out, sizeof(out), "%s: %d", argv[0], argc);
    printf("%s\n", out);
    return 0;
}
