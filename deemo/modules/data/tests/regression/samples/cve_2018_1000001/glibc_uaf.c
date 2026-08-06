/* CVE-2018-1000001 — glibc realpath() UAF
   Type: use_after_free
   gcc -O0 glibc_uaf.c -o glibc_uaf

   Simplified: realpath() could return a pointer to freed memory
   when the resolved path exceeded PATH_MAX. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_MAX 256

char *vuln_realpath(const char *path, char *resolved) {
    char *tmp = (char *)malloc(PATH_MAX);
    if (!tmp) return NULL;
    /* Simulated: path concatenation overflows, tmp is freed and reallocated */
    if (strlen(path) > PATH_MAX / 2) {
        free(tmp);
        tmp = (char *)malloc(strlen(path) + 1);
    }
    strcpy(tmp, path);  /* BUG: tmp may be the original freed pointer */
    if (resolved) strcpy(resolved, tmp);
    free(tmp);
    return (resolved) ? resolved : tmp;  /* tmp already freed → UAF */
}

int main() {
    char buf[PATH_MAX];
    char *result = vuln_realpath("/very/long/path/that/exceeds/the/limit/and/triggers/the/reallocation/path/continues/past/the/limit/and/keeps/going/until/it/overflows/the/buffer/causing/the/uaf/condition/to/trigger/in/the/realpath/function/call", buf);
    if (result) printf("Resolved: %s\n", result);
    return 0;
}
