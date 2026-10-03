/* CVE-2022-0185: legacy_parse_param 中 size 包含NUL但
 * 写入时额外追加, 造成2字节堆溢出.
 */
#include <stdlib.h>
#include <string.h>

int parse_param(const char *param, int plen, char *ctx) {
    int size = plen + 1;
    memcpy(ctx, param, size + 1);
    return size;
}

int main(int argc, char **argv) {
    (void)argc;
    char param[32];
    char *ctx = (char *)malloc(24);
    if (!ctx) return 1;
    memset(param, 'P', 24);
    parse_param(param, 24, ctx);
    free(ctx);
    return 0;
}
