/* CWE-122: Heap overflow via read() into malloc'd buffer with wrong size */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    char *buf = malloc(32);
    int fd = open(argv[1] ? argv[1] : "/dev/zero", O_RDONLY);
    read(fd, buf, 256); /* reads 256 into 32-byte heap buffer */
    close(fd); free(buf); return 0;
}
