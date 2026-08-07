#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int *m = (int *)malloc(50 * 50 * sizeof(int));
    if (!m) return 1;
    for (int i = 0; i < 50; i++)
        for (int j = 0; j < 50; j++)
            m[i * 50 + j] = i + j;   /* 内层界已知 */
    printf("[*] %d\n", m[0]);
    free(m);
    return 0;
}
