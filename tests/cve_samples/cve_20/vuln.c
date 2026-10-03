/* Double-free via aliased pointer / CWE-415 */
#include <stdlib.h>
void cleanup(char **p) { free(*p); }
void bug(void) {
    char *a = malloc(128);
    char *b = a; /* alias */
    cleanup(&a);
    free(b); /* double-free */
}
int main(void) { bug(); return 0; }
