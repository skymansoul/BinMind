#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-09: size_t被窄化为int — 在32位平台可能截断 */
int main(int argc, char **argv) {
    size_t real_size = 0x100000001ULL;
    int narrow = (int)(real_size & 0xFFFFFFFF);
    char *buf = (char *)malloc((size_t)narrow);
    if (!buf) return 1;
    memset(buf, 0, real_size);  /* VULNERABLE */
    free(buf); return 0;
}
