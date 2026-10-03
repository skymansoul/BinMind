/* FMT TN (safe) sample */
#include <stdio.h>
int main(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d-%d", 1, 2);
    printf("%s", buf);
    return 0;
}
