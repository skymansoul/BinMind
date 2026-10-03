/* CVE-2021-3156: sudo 的 argc/argv 合并逻辑在
 * argv[0] 以反斜杠结尾时未正确计算长度, 越界写.
 */
#include <stdlib.h>
#include <string.h>

char *join_args(int argc, char **argv) {
    size_t total = 0;
    for (int i = 0; i < argc; i++) total += strlen(argv[i]) + 1;
    char *buf = (char *)malloc(total);
    if (!buf) return 0;
    char *p = buf;
    for (int i = 0; i < argc; i++) {
        size_t n = strlen(argv[i]);
        if (n > 0 && argv[i][n - 1] == '\\') n += 1;
        memcpy(p, argv[i], n);
        p += n;
        *p++ = ' ';
    }
    *p = 0;
    return buf;
}

int main(int argc, char **argv) {
    char *joined = join_args(argc, argv);
    free(joined);
    return 0;
}
