#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* 模拟ollvm混淆的简单格式字符串漏洞——控制流平坦化风格 */
void vm_dispatch(int op, char *arg) {
    int state = 0;
    char *buf = NULL;
    while (1) {
        switch (state) {
        case 0: buf = malloc(256); state = 1; break;
        case 1: strcpy(buf, arg); state = 2; break;
        case 2:
            /* BUG: 混淆后的格式字符串漏洞——op==3时arg直接传给printf */
            if (op == 3) printf(arg);
            else printf("%s
", arg);
            state = 3; break;
        case 3: free(buf); return;
        }
    }
}
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    vm_dispatch(atoi(argv[1]), argv[2]);
    return 0;
}
