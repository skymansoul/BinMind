/* CVE-2021-3156 — sudo Baron Samedit 堆溢出 (strcpy 无界)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t n = 128;
    if (argc > 1) n = strlen(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    strcpy(buf, argv[1]);                 /* 无界 → 越界 */
    free(buf);
    return 0;
}
