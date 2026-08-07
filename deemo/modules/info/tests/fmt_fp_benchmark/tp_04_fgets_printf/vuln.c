/* FMT TP sample */
#include <stdio.h>
int main(void) {
    char buf[128];
    if (fgets(buf, sizeof(buf), stdin)) { printf(buf); }
    return 0;
}
