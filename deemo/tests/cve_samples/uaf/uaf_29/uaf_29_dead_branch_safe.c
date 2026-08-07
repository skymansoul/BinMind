/* UAF-29: Safe — free in dead branch (condition always false), use in live path (TN) */
#include <stdlib.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    if (0) {
        /* Dead code — never executed */
        free(buf);
    }
    /* SAFE: free only in dead branch */
    buf[0] = 'x';
    free(buf);
}

int main(void) {
    process();
    return 0;
}
