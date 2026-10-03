#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);              /* 用户输入作格式串 */
    printf("\n");
    return 0;
}
