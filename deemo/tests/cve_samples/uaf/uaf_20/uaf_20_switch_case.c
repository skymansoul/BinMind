/* UAF-20: Switch-case path — free in one case, use after switch (TP) */
#include <stdlib.h>
#include <string.h>

void process(int mode) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    switch (mode) {
        case 0:
            strcpy(buf, "mode0");
            break;
        case 1:
            free(buf);
            break;
        case 2:
            strcpy(buf, "mode2");
            break;
    }
    /* BUG: if mode==1, buf is freed */
    buf[0] = 'x';
}

int main(void) {
    process(0);
    process(1);
    process(2);
    return 0;
}
