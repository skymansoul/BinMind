#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_calloc_then_strcpy: Safe: calloc(128) + strcpy of shorter string
// Type: safe
int main(int argc, char **argv) {
    char src[1024];
    int n = argc > 1 ? atoi(argv[1]) : 128;
    memset(src, 0x41, sizeof(src));
    // Vulnerability: char *buf = calloc(1, 128); strcpy(buf, "short"); free(buf);
    char *buf = calloc(1, 128); strcpy(buf, "short"); free(buf);;
    return 0;
}
