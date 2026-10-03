/* off-by-one 结构体数组: for(i=0;i<=n;i++) 越界 1 元素 */
#include <stdlib.h>
typedef struct { int h; char d[64]; } Item;
void fill(Item* arr, int n) {
    for (int i = 0; i <= n; i++) arr[i].h = i;
}
int main() {
    Item* arr = malloc(10 * sizeof(Item));
    fill(arr, 10);
    free(arr);
    return 0;
}
