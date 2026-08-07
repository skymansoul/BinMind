#include <stdio.h>

int main(void) {
    int written = 0;
    /* VULN: controllable format with write capability */
    char *fmt = "AAAA%n";
    printf(fmt, &written);
    printf("bytes written: %d\n", written);
    return 0;
}
