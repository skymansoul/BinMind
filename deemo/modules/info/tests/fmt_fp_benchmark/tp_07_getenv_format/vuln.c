/* FMT TP sample */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *h = getenv("HOME");
    if (h) { printf(h); }
    return 0;
}
