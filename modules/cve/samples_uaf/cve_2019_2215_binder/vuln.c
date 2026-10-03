/* CVE-2019-2215 Android Binder: 释放 task_struct 后写入其字段. */
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p[0] = 'A';
    return 0;
}
