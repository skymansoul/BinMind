/* df_adv_19 — deep cross-function: A->B->C free chain
 * C frees, returns, A frees again
 */
#include <stdlib.h>
char *g_ptr = NULL;
void level_c() { free(g_ptr); }
void level_b() { level_c(); }
int main() {
    g_ptr = malloc(128);
    level_b();
    free(g_ptr);  /* double-free: g_ptr freed in level_c via level_b */
    return 0;
}
