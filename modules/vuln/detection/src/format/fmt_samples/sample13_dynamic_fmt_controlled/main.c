#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    if (argc < 2) return 1;
    /* format string partially from user input */
    snprintf(fmt, sizeof(fmt), "Value: %s", argv[1]);
    /* VULN: result contains user data as format */
    printf(fmt);
    printf("\n");
    return 0;
}
