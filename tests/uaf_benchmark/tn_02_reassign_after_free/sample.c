/* TN-02: Reassign After Free (SAFE) */
#include <stdlib.h>
#include <string.h>
void reassign_after_free(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    free(buf);
    buf = (char *)malloc(128);
    strcpy(buf, "safe data");
    free(buf);
}
int main(void) { reassign_after_free(); return 0; }