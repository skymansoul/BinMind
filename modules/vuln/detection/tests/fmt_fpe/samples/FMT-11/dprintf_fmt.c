
/* dprintf 格式串来自用户参数. */
#include <stdio.h>

static void send(int fd, char *user) {
    dprintf(fd, user);       /* 格式串 = 用户输入 */
}

int main(int argc, char **argv) {
    send(1, argv[1]);
    return 0;
}
