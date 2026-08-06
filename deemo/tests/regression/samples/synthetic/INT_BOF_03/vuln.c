/* CWE-190: Integer overflow in size computation for array index.
   idx * elem_size can overflow, leading to out-of-bounds access */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int idx = argc > 1 ? atoi(argv[1]) : 0x40000000;
    int elem_size = argc > 2 ? atoi(argv[2]) : 16;
    int *arr = calloc(256, sizeof(int));
    if (!arr) return 1;
    arr[idx * elem_size / elem_size] = 42; /* idx*elem_size may overflow */
    printf("%d\n", arr[0]);
    free(arr);
    return 0;
}
