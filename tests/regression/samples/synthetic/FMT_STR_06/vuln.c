/* CWE-134: err() family — errx/warnx take format string.
   errx(1, user_input) treats user_input as format */
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    warnx(argv[1]); /* argv[1] as format string */
    return 0;
}
