/* fprintf stdout, 格式串来自输入. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc < 2) return 0;
    strncpy(buf, argv[1], 63);
    buf[63] = 0;
    fprintf(stdout, buf);
    return 0;
}
