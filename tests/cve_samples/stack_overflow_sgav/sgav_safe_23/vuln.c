/* SAFE: arr[i] 前有 i < 10 的边界检查 */
#include <stdlib.h>
int main(int argc, char **argv) {
    int arr[10];
    int i = argc > 1 ? atoi(argv[1]) : 5;
    if (i >= 0 && i < 10) {
        arr[i] = 42;
    }
    return 0;
}
