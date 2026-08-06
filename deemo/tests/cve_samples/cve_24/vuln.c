/* Heap overflow via realloc misuse / CWE-122 */
#include <stdlib.h>
#include <string.h>
void extend(char **p, int old_sz, int new_sz) {
    *p = realloc(*p, new_sz);
    memset(*p + old_sz, 0, new_sz); /* BUG: writes new_sz bytes, not (new_sz-old_sz) */
}
int main(void) { char *b = malloc(64); extend(&b, 64, 256); free(b); return 0; }
