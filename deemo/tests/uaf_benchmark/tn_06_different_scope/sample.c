/* TN-06: Different Scope reassign (SAFE) */
#include <stdlib.h>
static char *g_ptr = NULL;
void init(void) { g_ptr = (char *)malloc(128); }
void cleanup(void) { if (g_ptr) { free(g_ptr); g_ptr = NULL; } }
void use(void) {
    if (!g_ptr) { g_ptr = (char *)malloc(64); }
    if (g_ptr) { g_ptr[0] = 'G'; }
}
int main(void) { init(); cleanup(); use(); free(g_ptr); return 0; }