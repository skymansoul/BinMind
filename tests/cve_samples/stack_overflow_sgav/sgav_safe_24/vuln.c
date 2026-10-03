/* SAFE: 递归函数但栈帧很小(仅4字节局部变量) */
#include <stdio.h>
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
int main() {
    printf("%d\n", factorial(10));
    return 0;
}
