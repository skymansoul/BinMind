/* CWE-134: setproctitle format string (BSD) */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    setproctitle(argv[1]);
    return 0;
}
