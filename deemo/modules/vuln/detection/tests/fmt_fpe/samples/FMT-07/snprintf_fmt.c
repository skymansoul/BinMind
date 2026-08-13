
/* snprintf 格式串来自用户参数. */
#include <stdio.h>

static void pack(char *user) {
    char out[64];
    snprintf(out, 64, user); /* 格式串 = 用户输入 */
}

int main(int argc, char **argv) {
    pack(argv[1]);
    return 0;
}
