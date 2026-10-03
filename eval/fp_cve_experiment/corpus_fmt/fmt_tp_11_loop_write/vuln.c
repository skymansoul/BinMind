/* FMT-TP-11: 循环拼接形成格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[128] = "";
    const char *seg = argc > 1 ? argv[1] : "%d";
    for (int i = 0; i < 4 && strlen(fmt) < 100; i++) {
        strcat(fmt, seg);
    }
    printf(fmt, 1, 2, 3, 4);
    return 0;
}
