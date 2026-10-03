#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char g_buf[64];

int main(int argc, char **argv) {
    char stack_buf[64];
    char *q = stack_buf;
    free(q);
    q[0] = 'X';
    char *gp = g_buf;
    free(gp);
    gp[0] = 'Y';
    printf("%c%c\n", q[0], gp[0]);
    return 0;
}
