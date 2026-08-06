/* Stack overflow sample — memcpy to fixed stack buffer / CWE-121 */
#include <string.h>
#include <stdlib.h>
void process(char *input, int len) {
    char buf[128];
    memcpy(buf, input, len); /* BUG: len unchecked */
}
int main(void) {
    char *d = malloc(512); memset(d,'S',512);
    process(d, 512); free(d); return 0;
}
