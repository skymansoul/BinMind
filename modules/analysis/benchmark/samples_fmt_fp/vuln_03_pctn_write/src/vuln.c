#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);              /* 攻击者可控 %n 写任意地址 */
    return 0;
}
