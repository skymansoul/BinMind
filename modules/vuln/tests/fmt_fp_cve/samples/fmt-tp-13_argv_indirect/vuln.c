/* argv 指针数组间接传递. */
#include <stdio.h>
int main(int argc, char **argv) {
    char **p = argv;
    if (argc < 2) return 0;
    printf(p[1]);
    return 0;
}
