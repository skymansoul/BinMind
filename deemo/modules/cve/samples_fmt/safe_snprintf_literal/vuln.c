/* N/A 安全对照: snprintf 有界字面量格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[64];
    snprintf(dst, sizeof(dst), "%s", argc > 1 ? argv[1] : "none");
    puts(dst);
    return 0;
}
