/* sprintf 写缓冲, 格式串用户可控. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char out[128];
    if (argc < 2) return 0;
    sprintf(out, argv[1]);
    return 0;
}
