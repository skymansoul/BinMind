/* df_adv_31 — double-free with NULL check bypass
 * First free in conditional, second free after conditional without NULL reset
 * if(x) { free(p); } ... free(p);
 * The NULL guard is checked but not set after first free
 */
#include <stdlib.h>
#include <string.h>
void process(char *data, int mode) {
    if (mode == 1) {
        free(data);
        /* data not nulled */
    }
    if (data != NULL) {  /* data still non-NULL even after free */
        free(data);  /* double-free when mode==1 */
    }
}
int main() { char *p = malloc(64); process(p, 1); return 0; }
