/* snprintf 限长但格式串用户可控. */
#include <stdio.h>
int main(int argc, char **argv) {
    char out[128];
    if (argc < 2) return 0;
    snprintf(out, 128, argv[1]);
    return 0;
}
