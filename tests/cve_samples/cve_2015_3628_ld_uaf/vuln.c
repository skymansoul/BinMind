/* CVE-2015-3628 — GNU ld UAF via malformed input file
 * 类型: use_after_free / CWE-416 */
#include <stdlib.h>
typedef struct { int id; char *name; } sym_t;
static sym_t *g_sym = NULL;
void process_symbol(void) {
    g_sym = malloc(sizeof(sym_t)); g_sym->id = 1;
    free(g_sym);  /* BUG: g_sym not set to NULL */
    if (g_sym) g_sym->id = 2; /* UAF */
}
int main(void) { process_symbol(); return 0; }
