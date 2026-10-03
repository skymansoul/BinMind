/* CWE-416: UAF via global pointer alias
   free(g_ptr) then use through alias in callback */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *g_ptr = NULL;
void cleanup(void) { free(g_ptr); }
void use_ptr(void) {
    if (g_ptr) printf("%s\n", g_ptr); /* UAF after cleanup() */
}
int main(void) {
    g_ptr = strdup("sensitive data");
    if (!g_ptr) return 1;
    use_ptr();
    cleanup();
    use_ptr(); /* UAF here */
    return 0;
}
