/* CVE-2018-17182 vmacache: 键误匹配导致释放对象被 memcpy 读取. */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    char dst[64];
    if (!p) return 1;
    free(p);
    memcpy(dst, p, 16);
    return 0;
}
