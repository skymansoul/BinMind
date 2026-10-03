#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct rec { int id; char name[32]; double score; };  /* 48 字节 */
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 10;
    n &= 0xFFFF;                       /* 掩码: n <= 65535 */
    struct rec *arr = (struct rec *)malloc(n * sizeof(struct rec));
    if (!arr) return 1;
    for (unsigned i = 0; i < n; i++) {
        arr[i].id = (int)i;
        arr[i].score = 1.0;
    }
    free(arr);
    return 0;
}
