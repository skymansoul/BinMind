/* VULN: arr[i] 其中 i 来自用户输入无边界检查 */
#include <stdlib.h>
int main(int argc, char **argv) {
    int arr[10];
    int i = argc > 1 ? atoi(argv[1]) : 9;
    arr[i] = 42;
    return 0;
}
