/* INT-006: Addition overflow in offset calculation */
#include <stdlib.h>
#include <string.h>
void access(char *buf, int base, int user_offset) {
    int idx = base + user_offset;
    if (idx < 0) return;
    char *p = buf + idx;
    *p = 'x'; /* BUG: idx may overflow past positive bound */
}
int main(void) {
    char *b = malloc(256);
    access(b, 200, 2147483600);
    free(b); return 0;
}
