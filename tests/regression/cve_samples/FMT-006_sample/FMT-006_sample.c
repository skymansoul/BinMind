/* FMT-006: SAFE — snprintf with size limit */
#include <stdio.h>
void format_output(const char *name) {
    char buf[256];
    snprintf(buf, sizeof(buf), "Hello, %s!", name);
    printf("%s\n", buf);
}
int main(int argc, char **argv) {
    if (argc > 1) format_output(argv[1]);
    return 0;
}
