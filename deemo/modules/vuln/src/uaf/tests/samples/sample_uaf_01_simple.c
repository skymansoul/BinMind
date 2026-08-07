/* sample_uaf_01_simple.c — 最简UAF: free后立即use */
#include <stdlib.h>
int main() {
    int *p = (int*)malloc(64);
    *p = 42;
    free(p);
    *p = 99;  /* UAF: p is freed */
    return 0;
}
