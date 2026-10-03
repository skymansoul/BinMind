/* CWE-416: UAF when free() called in signal handler while main() uses ptr */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
static char *g_buf;
void handler(int s) { free(g_buf); }
int main(void) {
    g_buf = malloc(64); signal(SIGALRM, handler);
    alarm(1); sleep(2); puts(g_buf); return 0;
}
