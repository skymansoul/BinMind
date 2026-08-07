/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    int fd = 0;
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    read(fd, buf, 1024);
    free(buf);
    return 0;
}
