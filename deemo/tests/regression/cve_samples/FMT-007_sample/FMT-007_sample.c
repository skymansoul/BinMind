/* FMT-007: Indirect format string via wrapper function */
#include <stdio.h>
void my_printf(const char *fmt, ...) { printf(fmt); }
int main(int argc, char **argv) {
    if (argc > 1) my_printf(argv[1]);
    return 0;
}
