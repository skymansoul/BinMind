/* FMT TP sample */
#include <stdio.h>
int main(void) {
    char buf[64];
    recv(0, buf, sizeof(buf), 0);
    printf(buf);
    return 0;
}
