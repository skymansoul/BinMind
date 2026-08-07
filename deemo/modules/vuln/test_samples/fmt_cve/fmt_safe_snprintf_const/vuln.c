/* fmt_safe_snprintf_const — snprintf 常量格式 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[64];
    snprintf(dst, sizeof(dst), "x=%d", argc);
    puts(dst);
    return 0;
}
