/* CWE-134: dprintf with user format string.
   dprintf(fd, user_fmt, ...) — less common but same vulnerability class */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int fd = open("/dev/null", O_WRONLY);
    dprintf(fd, argv[1]); /* user fmt to dprintf */
    close(fd);
    return 0;
}
