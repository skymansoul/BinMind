/* fgets 后手工终止越界: buf[len-1] 已满仍写 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main() {
    char* b = malloc(16);
    if (fgets(b, 16, stdin)) {
        int l = (int)strlen(b);
        if (l > 0) { b[l - 1] = 0; }
    }
    free(b);
    return 0;
}
