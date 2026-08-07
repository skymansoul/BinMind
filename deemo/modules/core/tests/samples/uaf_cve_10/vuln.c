// CVE-2023-2033: Error path UAF — cleanup frees, error handler uses
#include <stdlib.h>
#include <stdio.h>

typedef struct { int status; char *msg; } Conn;

void log_error(Conn *c) {
    printf("err: %s\n", c->msg);         // @uaf_use — c might be freed
}

int vuln_error_path_uaf(int should_fail) {
    Conn *c = (Conn*)malloc(sizeof(Conn));  // @uaf_alloc
    c->status = 0;
    if (should_fail) {
        free(c);                            // @uaf_free — cleanup
        log_error(c);                       // UAF: use after cleanup
        return -1;
    }
    c->status = 200; free(c);
    return 0;
}
int main() { vuln_error_path_uaf(1); return 0; }