/* CWE-121: Stack overflow via sprintf with variable-length format output */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[64];
    sprintf(buf, "User: %s, Role: %s, Path: %s",
            argc>1?argv[1]:"guest", argc>2?argv[2]:"none", argc>3?argv[3]:"/");
    puts(buf);
    return 0;
}
