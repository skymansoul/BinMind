#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buffers[4];
    for (int i = 0; i < 4; i++) {
        buffers[i] = (char *)malloc(32);
        if (buffers[i]) sprintf(buffers[i], "buf%d", i);
    }
    for (int i = 0; i < 4; i++) {
        free(buffers[i]);
        if (i > 0) {
            /* UAF: buffers[i-1] already freed */
            printf("prev: %s\n", buffers[i-1]);
        }
    }
    return 0;
}
