/* VULN: 递归函数 + 4KB 栈帧 → 栈耗尽 */
#include <stdio.h>
void recurse(int depth) {
    char local[4096];
    if (depth > 0) recurse(depth - 1);
}
int main(int argc, char **argv) {
    int d = argc > 1 ? atoi(argv[1]) : 100;
    recurse(d);
    return 0;
}
