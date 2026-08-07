/* taint传播: malloc(64)+memcpy(atoi(argv))
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int taint_overflow(int argc, char **argv) {
    char *buf = malloc(64);
    if (!buf) return -1;
    int len = atoi(argv[1]);
    memcpy(buf, src, len);
    free(buf);
    return 0;
}
