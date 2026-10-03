/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    snprintf(buf, 128, "%s-%d", "PREFIX", 42);
    free(buf);
    return 0;
}
