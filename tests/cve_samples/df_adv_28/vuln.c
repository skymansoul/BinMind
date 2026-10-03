/* df_adv_28 — double-free via array of pointers
 * arr[0] and arr[2] point to same allocation; free both
 */
#include <stdlib.h>
int main() {
    char **arr = malloc(4 * sizeof(char*));
    arr[0] = malloc(64);
    arr[2] = arr[0];  /* alias through array */
    free(arr[0]);
    free(arr[2]);  /* double-free: arr[2] aliases arr[0] */
    free(arr);
    return 0;
}
