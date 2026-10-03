/* FMT TP sample */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char fmt[256];
    if (argc > 1) {
        strcpy(fmt, argv[1]);
        printf(fmt);
    }
    return 0;
}
