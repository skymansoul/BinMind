/* df_adv_17 — VULN: conditional NULL not covering all paths
 * free(p) then if(argc>100) p=NULL; if(p!=NULL) free(p)
 * When argc<=100: p remains non-NULL, guard passes => double-free
 */
#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = malloc(64);
    free(p);
    if (argc > 100) {
        p = NULL;
    }
    if (p != NULL) {
        free(p);  /* double-free when argc<=100: p was freed but not nulled */
    }
    return 0;
}
