/* FMT-001: Direct printf(user_input) */
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) printf(argv[1]); /* FORMAT STRING */
    return 0;
}
