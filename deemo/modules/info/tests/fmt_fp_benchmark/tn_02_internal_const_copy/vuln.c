/* FMT TN (safe) sample */
#include <stdio.h>
#include <string.h>
int main(void) {
    char fmt[64];
    strcpy(fmt, "value=%d\n");
    printf(fmt, 42);
    return 0;
}
