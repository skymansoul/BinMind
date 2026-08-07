/* SAFE - for(i=0;i<n;i++) 正确边界 */
#include <stdlib.h>
typedef struct { int h; char d[64]; } Item;
void fill_ok(Item* arr, int n) {
    for (int i = 0; i < n; i++) arr[i].h = i;
}
int main() {
    Item* arr = malloc(10 * sizeof(Item));
    fill_ok(arr, 10);
    free(arr);
    return 0;
}
