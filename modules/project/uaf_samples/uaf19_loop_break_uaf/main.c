#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    int i;
    for (i = 0; i < 4; i++) {
        if (i == 2) {
            free(p);
            break;
        }
    }
    p[0] = 'C';
    printf("%c\n", p[0]);
    return 0;
}
