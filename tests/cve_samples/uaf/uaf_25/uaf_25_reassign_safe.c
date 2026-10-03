/* UAF-25: Safe — free followed by immediate reassign, use after reassign (TN) */
#include <stdlib.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "old data");
    free(buf);
    /* SAFE: buf reassigned immediately after free */
    buf = (char *)malloc(256);
    if (!buf) return;
    strcpy(buf, "new data");
    buf[0] = 'x';
    free(buf);
}

int main(void) {
    process();
    return 0;
}
