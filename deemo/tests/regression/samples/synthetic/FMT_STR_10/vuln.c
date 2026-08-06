/* CWE-134: custom logger that passes user string to printf */
#include <stdio.h>
static void mylog(const char *s) { printf(s); printf("\n"); }
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[256];
    snprintf(buf, 256, "user said: %s", argv[1]);
    mylog(buf);
    return 0;
}
