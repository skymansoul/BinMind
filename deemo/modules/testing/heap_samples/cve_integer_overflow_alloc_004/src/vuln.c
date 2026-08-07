/* nmemb*size overflow => allocate few bytes, write many */
#include <stdio.h>
#include <stdlib.h>
static void *alloc_array(size_t n, size_t sz) {
    return malloc(n * sz);  /* BUG: no overflow check */
}
int main(void) {
    size_t n = 0x40000001;
    int *arr = (int *)alloc_array(n, sizeof(int));
    if (!arr) return 1;
    for (size_t i = 0; i < 100; i++) arr[i] = (int)i;  /* BUG: overflow */
    printf("[*] arr[99]=%d\n", arr[99]);
    free(arr);
    return 0;
}
