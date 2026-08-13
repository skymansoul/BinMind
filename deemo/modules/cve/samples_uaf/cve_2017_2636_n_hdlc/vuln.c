/* CVE-2017-2636 n_hdlc 驱动: 竞争路径释放对象后 strlen 读取. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    size_t n = strlen(p);
    printf("len=%zu\n", n);
    return 0;
}
