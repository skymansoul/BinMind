#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt_buf[16];
    if (argc < 2) return 1;
    /* overflow fmt_buf → can inject format specifiers */
    snprintf(fmt_buf, sizeof(fmt_buf), "Value: %s", argv[1]);
    printf(fmt_buf);  /* potential vuln if overflow injects % */
    printf("\n");
    return 0;
}
