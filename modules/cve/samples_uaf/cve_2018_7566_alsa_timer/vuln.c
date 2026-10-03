/* CVE-2018-7566 ALSA timer: snd_timer_user 释放后 memset 写入. */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    memset(p, 0, 16);
    return 0;
}
