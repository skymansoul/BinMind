/* FMT-TP-09: fgets 读入格式串后 printf. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char fmt[128];
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
        strcpy(fmt, "default %x");
    }
    printf(fmt);
    return 0;
}
