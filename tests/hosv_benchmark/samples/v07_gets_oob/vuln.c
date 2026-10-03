/* gets 无界读入堆缓冲 */
#include <stdlib.h>
#include <stdio.h>
int main() {
    char* b = malloc(48);
    gets(b);
    free(b);
    return 0;
}
