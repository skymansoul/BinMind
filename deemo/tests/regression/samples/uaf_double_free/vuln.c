#include <stdio.h>
#include <stdlib.h>
/* CVE-2022-0185 模式: 双重释放 */
void cleanup(char *p) {
    if (p) { free(p); }
}
int main() {
    char *buf = malloc(128);
    cleanup(buf);
    /* BUG: buf已被cleanup释放, 再次释放 */
    free(buf);
    return 0;
}
