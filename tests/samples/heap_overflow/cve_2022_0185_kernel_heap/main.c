/* CVE-2022-0185-like: legacy param overflow — duplicate entry */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int len = argc > 1 ? atoi(argv[1]) : 5000;
    char *buf = malloc(1024);
    if (!buf) return 1;
    memset(buf, 0, len);  /* overflow if len > 1024 */
    free(buf);
    return 0;
}
