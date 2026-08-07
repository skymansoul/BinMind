/* safe_guard_bounded — 有界守卫保护 (TN, 误报削减目标)。
 * 守卫 len<=64 保证写入不越界。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t len = 32;
    if (argc > 1) len = strlen(argv[1]);
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (len <= 64) {                      /* 有界守卫 */
        memcpy(buf, argv[1], len);
    }
    free(buf);
    return 0;
}
