#include <stdio.h>
/* FMT-05: 位置参数 — %n$ 可以跳过参数到达任意栈位置 */
int main(int argc, char **argv) {
    int a=1, b=2, c=3, d=4, e=5, f=6, g=7, h=8;
    if (argc > 1)
        printf(argv[1], a,b,c,d,e,f,g,h);  /* VULNERABLE: %8$x泄露第8个参数 */
    return 0;
}
