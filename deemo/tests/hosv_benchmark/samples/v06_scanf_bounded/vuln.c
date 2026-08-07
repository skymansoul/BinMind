/* SAFE - scanf %31s 有界输入 */
#include <stdlib.h>
#include <stdio.h>
int main() {
    char* b = malloc(32);
    scanf("%31s", b);
    free(b);
    return 0;
}
