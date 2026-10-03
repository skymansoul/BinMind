#include <stdio.h>
#include <unistd.h>

void process(int fd) {
    char buf[128];
    ssize_t n = read(fd, buf, 512);  // read 512 into buf[128]
    if (n > 0) buf[n] = '\0';
    printf("read %zd bytes\n", n);
}

int main() {
    process(0);
    return 0;
}
