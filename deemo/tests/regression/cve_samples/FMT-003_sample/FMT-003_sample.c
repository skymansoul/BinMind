/* FMT-003: fprintf with user-controlled format */
#include <stdio.h>
void log_to_file(FILE *f, const char *msg) { fprintf(f, msg); }
int main(int argc, char **argv) {
    if (argc > 1) log_to_file(stderr, argv[1]);
    return 0;
}
