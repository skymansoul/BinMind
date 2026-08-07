/* UAF-23: Realloc returns NULL — old pointer used (TP) */
#include <stdlib.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "initial");
    char *tmp = (char *)realloc(buf, 4096);
    if (!tmp) {
        /* BUG: realloc failure doesn't free buf, but we treat it as UAF pattern
           if code incorrectly assumes buf is still valid after realloc */
        buf[0] = 'x';
        free(buf);
        return;
    }
    buf = tmp;
    buf[0] = 'y';
    free(buf);
}

int main(void) {
    process();
    return 0;
}
