#include <stdio.h>

int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "default";
    /* SAFE: constant format string, user data as argument */
    printf("User input: %s\n", user);
    return 0;
}
