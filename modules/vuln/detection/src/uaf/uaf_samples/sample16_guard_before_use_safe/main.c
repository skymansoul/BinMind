#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *data = (int *)malloc(sizeof(int) * 10);
    if (!data) return 1;
    for (int i = 0; i < 10; i++) data[i] = i;
    free(data);
    data = NULL;
    /* safe: always null-checked after potential free */
    if (data != NULL) {
        data[0] = 999;  /* unreachable */
    }
    printf("guarded: safe\n");
    return 0;
}
