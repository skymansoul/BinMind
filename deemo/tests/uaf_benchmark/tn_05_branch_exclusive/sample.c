/* TN-05: Branch-Exclusive free/use (SAFE) */
#include <stdlib.h>
#include <string.h>
void branch_exclusive(int mode) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    if (mode == 0) { free(buf); return; }
    else { strcpy(buf, "mode 1"); free(buf); }
}
int main(void) { branch_exclusive(1); return 0; }