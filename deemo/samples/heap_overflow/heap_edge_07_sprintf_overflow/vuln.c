/* sprintf into fixed buffer with variable content */
#include <stdlib.h>
#include <stdio.h>

void edge_sprintf_overflow(char *user_input) {
    char *buf = (char *)malloc(32);
    if (buf) {
        sprintf(buf, "User input: %s", user_input);  /* unbounded �� OVERFLOW */
        free(buf);
    }
}

int main(void) {
    static char in[] =
        "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
        "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    edge_sprintf_overflow(in);  /* "User input: " + in > 32-byte buf */
    return 0;
}
