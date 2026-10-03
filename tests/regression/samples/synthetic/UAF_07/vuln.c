/* CWE-416: UAF via conditional free - one branch frees, another uses.
   Static analyzer must track both paths to detect the UAF on the else branch. */
#include <stdio.h>
#include <stdlib.h>
void process(int mode, char *data) {
    char *buf = malloc(256);
    snprintf(buf, 256, "%s", data);
    if (mode == 0) {
        printf("mode0: %s\n", buf);
        free(buf);
    } else {
        printf("mode1: %s\n", buf);
        /* missing free on this path - but also no UAF */
    }
    /* buf may be freed if mode==0, used here unconditionally */
    printf("result: %s\n", buf);
}
int main(int argc, char **argv) {
    process(argc > 1 ? atoi(argv[1]) : 0, "test");
    return 0;
}
