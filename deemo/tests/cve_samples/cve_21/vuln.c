/* Integer overflow in size calculation leading to heap overflow / CWE-190→CWE-122 */
#include <stdlib.h>
#include <string.h>
void alloc_and_copy(int n, int m) {
    int total = n * m; /* BUG: overflow if n*m > INT_MAX */
    char *buf = malloc(total);
    memcpy(buf, "data", n * m); /* heap overflow via integer wrap */
    free(buf);
}
int main(void) { alloc_and_copy(65536, 65536); return 0; }
