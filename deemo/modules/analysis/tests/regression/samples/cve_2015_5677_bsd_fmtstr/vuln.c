#include <stdio.h>
void log_event(const char *input) {
    char buf[256];
    snprintf(buf, sizeof(buf), input); /* BUG: input used as format string */
    printf("LOG: %s", buf);
}
int main(int a, char **v) { if(a<2) return 1;
    log_event(v[1]); return 0; }