#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x1000;
    char *buf = (char *)malloc(n << 20);  /* n<<20 溢出 */
    if (!buf) return 1;
    memset(buf, 'A', 0x100000);           /* 远超实际分配 */
    free(buf);
    return 0;
}
