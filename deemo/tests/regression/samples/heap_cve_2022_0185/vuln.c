/* CVE-2022-0185 — Linux kernel fs/fs_context heap overflow
 * Pattern: 整数溢出导致 alloc size 过小, 后续写入溢出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_option(const char *opt, size_t opt_len) {
    /* BUG: opt_len + 1 可能 wraparound 到 0 或极小值 */
    char *buf = (char *)malloc(opt_len + 1);
    if (!buf) return;
    memcpy(buf, opt, opt_len);  /* HEAP OVERFLOW if opt_len > alloc_size */
    buf[opt_len] = 0;
    printf("%s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        size_t len = (size_t)atol(argv[1]);
        parse_option("AAAA", len);
    }
    return 0;
}
